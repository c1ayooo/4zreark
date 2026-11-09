// Package useragent 提供按站点确定的伪装 UA 会话。
//
// 目标：同一个站（默认 host，含端口）在整条信息收集链路里使用同一个 UA，
// 跨阶段、跨任务、跨节点可复现；不同站之间使用不同的 UA，避免全平台
// 一个 UA 形成可关联指纹。
//
// 生成方式：HMAC-SHA256(seed, siteKey) 取前 8 字节选池，O(1)、无锁、无状态。
// seed 由任务级 context 携带（master 派生后随任务下发），worker 不持库也能复现。
package useragent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
)

// Desktop 是常见桌面浏览器 UA。池内顺序是稳定契约：改动会让同一站点的
// UA 发生变化，除非同时升级 seed 版本。
var Desktop = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
}

// Mobile 是手机浏览器 UA；仅在显式需要的场景使用（同站一致性优先，
// 不再作为 403 自动重试的换 UA 手段）。
var Mobile = []string{
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
}

// languages 与 Desktop 等长，保证同一索引取到配套的 Accept-Language。
var languages = []string{
	"zh-CN,zh;q=0.9,en;q=0.8",
	"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
	"en-US,en;q=0.9,zh-CN;q=0.8",
	"en-US,en;q=0.9",
	"zh-CN,zh;q=0.9,en;q=0.8",
	"en-US,en;q=0.9,zh-CN;q=0.8",
}

// Session 是一个站点在整条链路上使用的请求身份。
type Session struct {
	UserAgent      string
	AcceptLanguage string
	AcceptEncoding string
}

// Apply 把会话写入请求头。
func (s Session) Apply(req *http.Request) {
	if req == nil {
		return
	}
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	if s.AcceptLanguage != "" {
		req.Header.Set("Accept-Language", s.AcceptLanguage)
	}
	if s.AcceptEncoding != "" {
		req.Header.Set("Accept-Encoding", s.AcceptEncoding)
	}
}

// ForSite 按 seed + 站点键确定性生成会话。相同入参永远得到相同 UA。
func ForSite(seed, siteKey string) Session {
	key := strings.TrimSpace(siteKey)
	if key == "" {
		return Session{
			UserAgent:      Pick(),
			AcceptLanguage: languages[0],
			AcceptEncoding: "gzip, deflate",
		}
	}
	if strings.TrimSpace(seed) == "" {
		// seed 缺失（例如未配置密钥的单机调试）也不能退化成随机：
		// 用固定盐保证同站同 UA，跨进程可复现。
		seed = defaultSeed
	}
	mac := hmac.New(sha256.New, []byte(seed))
	_, _ = mac.Write([]byte("ua:v1:" + key))
	sum := mac.Sum(nil)
	idx := int(binary.BigEndian.Uint64(sum[:8]) % uint64(len(Desktop)))
	return Session{
		UserAgent:      Desktop[idx],
		AcceptLanguage: languages[idx%len(languages)],
		AcceptEncoding: "gzip, deflate",
	}
}

const defaultSeed = "4zreark-ua-v1"

// DeriveSeed 由项目维度派生任务级 seed。master 建任务时写入 TaskConfig，
// worker 直接消费；同一项目下所有站点共享 seed，但站点键仍不同。
func DeriveSeed(secret string, projectID int64) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		secret = defaultSeed
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "project:%d", projectID)
	return hex.EncodeToString(mac.Sum(nil))
}

// Secret 返回派生 seed 的主密钥。按优先级取专用 UA 密钥、数据源加密密钥、
// JWT 密钥；都没有时返回空串（ForSite 会用固定盐兜底）。
func Secret() string {
	for _, name := range []string{"ZRE_UA_SEED_SECRET", "ZRE_SECRET_KEY", "ZRE_JWT_SECRET"} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return ""
}

// ---- context 传播 ----

type sessionKey struct{}
type seedKey struct{}

// WithSession 把一个已确定的会话放进 ctx。
func WithSession(ctx context.Context, s Session) context.Context {
	if ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFromContext 读取显式会话。
func SessionFromContext(ctx context.Context) (Session, bool) {
	if ctx == nil {
		return Session{}, false
	}
	s, ok := ctx.Value(sessionKey{}).(Session)
	return s, ok
}

// WithSeed 把任务级 seed 放进 ctx。下游 Apply 会按请求 URL 的 host 自动派生。
func WithSeed(ctx context.Context, seed string) context.Context {
	if ctx == nil || strings.TrimSpace(seed) == "" {
		return ctx
	}
	return context.WithValue(ctx, seedKey{}, seed)
}

// SeedFromContext 读取任务级 seed。
func SeedFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(seedKey{}).(string)
	return s
}

// ---- 兼容旧调用 ----

func Pick() string       { return Desktop[rand.IntN(len(Desktop))] }
func PickMobile() string { return Mobile[rand.IntN(len(Mobile))] }

// Apply 是统一入口：优先 ctx 里的显式会话，其次按 ctx seed + 请求 host 派生，
// 最后才随机。这样纯 Go 客户端只要在建请求前把任务 ctx 带上，就能自动做到
// 「同站同 UA」，不需要每个 scanner 改签名。
func Apply(req *http.Request) {
	if req == nil {
		return
	}
	if s, ok := SessionFromContext(req.Context()); ok {
		s.Apply(req)
		return
	}
	seed := SeedFromContext(req.Context())
	host := ""
	if req.URL != nil {
		host = req.URL.Host
	}
	// 即使没有 task seed（后台巡检 / 单机调试），也按 host 用固定盐派生，
	// 保证同一个站稳定，而不是每次请求随机。
	if host != "" {
		ForSite(seed, host).Apply(req)
		return
	}
	req.Header.Set("User-Agent", Pick())
	req.Header.Set("Accept-Language", languages[0])
	req.Header.Set("Accept-Encoding", "gzip, deflate")
}

// ApplyMobile 保留给显式移动端场景；不再用于 403 自动换 UA。
func ApplyMobile(req *http.Request) {
	req.Header.Set("User-Agent", PickMobile())
}

// Transport 兜底覆盖工具型 UA。请求若带站点会话/seed，按站点派生；
// 否则回退随机，避免出现 Go-http-client 这类可识别标识。
type Transport struct{ Base http.RoundTripper }

func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	clone := req.Clone(req.Context())
	Apply(clone)
	return base.RoundTrip(clone)
}
