// Package vhostdedup 实现站点默认后端去噪（catch-all vhost）的判定与基线探针。
//
// 同一台源站常把任意 Host 都路由到同一张默认页（nginx default_server、域名
// 停放页、泛解析兜底页），流水线按子域逐个探测时会把这一页重复入库成 N 个
// 「站点」。本包借 internal/diffprobe「基线-变体测量」的思路（同构不同码）：
// 对目标 IP 发少量随机 Host 探针测出默认后端基线（状态码/长度分桶/标题），
// 候选站点与基线同形（标题一致 + 长度同桶）且无业务特征（favicon 与基线不同、
// 有独立标题都算业务站点，放行）才剔除；基线漏网的由调用方按「同 IP 同形态」
// 聚类兜底打标。
//
// 设计红线：
//   - 基线探针只对「有站点候选的 IP」发（由调用方保证），每 IP 最多
//     MaxBaselineProbes 个请求；
//   - 任何探针失败（传输错误/超时/两次观测不一致）= 放弃去噪，调用方放行全部
//     候选——宁可漏杀不可误杀；
//   - 判定逻辑（LooksLikeBaseline / MarkClusters）是纯函数，探针层只负责测量，
//     前者无需网络即可单测。
package vhostdedup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 阈值与探针形态常量（参照 pipeline.honeypot 的写法：常量 + 依据写在包内）。
const (
	// MaxBaselineProbes 每个 IP 的随机 Host 基线探针数上限，也是每 IP 基线请求的
	// 成本红线。单次采样无法排除源站随机噪声（动态内容/反侦察轮换），两次观测
	// 同形才认基线成立。
	MaxBaselineProbes = 2
	// ClusterMinGroup 同 IP 同形态（FormKey 相同）站点数达到该值整组打标（聚类
	// 兜底）。正常业务服务器同一 IP 上极少有 ≥10 个状态码/长度桶/标题完全一致
	// 的独立站点，达到该量级基本是默认页/停放页阵列；兜底只打标不剔除。
	ClusterMinGroup = 10
	// defaultProbeTimeout 单个基线探针的默认超时，与流水线 HTTP 指纹阶段的
	// 客户端超时对齐。探针复用调用方的 *http.Client（超时/代理出口/安全拨号
	// 全部继承），这里是请求 ctx 的兜底上限，测试可调小。
	defaultProbeTimeout = 10 * time.Second
	// randomHostSuffix 随机 Host 的固定后缀。.invalid 是 RFC 2606 保留 TLD，
	// 不可能与任何真实业务域名撞车；按 Host 路由的源站会把它送进默认后端。
	randomHostSuffix = ".invalid"
	// randomHostLabelLen 随机标签的 hex 长度（固定）。部分默认页会把 Host 回显
	// 进页面，固定长度让基线响应长度不随 Host 长度抖动，长度分桶才可比。
	randomHostLabelLen = 12
	// maxProbeBody 基线探针读取响应体的上限，与 fingerprint 的 maxBodyScan 同
	// 口径：候选观测同样截到 512KB 提取标题/长度，两边长度才可比。
	maxProbeBody = 512 * 1024
)

// probeUserAgent / probeAccept 与 fingerprint.probeOne 的请求头保持同款浏览器
// 形态：基线探针必须和候选探测长得一样，源站按 UA 差异化响应时两边的观测才可比。
const (
	probeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
	probeAccept    = "text/html,application/xhtml+xml,*/*;q=0.8"
)

// Response 是一次 HTTP 观测参与去噪判定的最小摘要：基线测量的三要素
// （状态码/长度/标题）外加 favicon 哈希。
type Response struct {
	StatusCode  int    // 状态码原样记录：404/403 的兜底页同样是默认后端形态
	BodyLen     int    // 响应体字节长度（与候选观测同口径，截断前）
	Title       string // <title> 文本
	FaviconMMH3 string // favicon mmh3（fofa 风格）；空表示无 favicon
}

// LengthBucket 长度分桶：「长度同桶」的口径是按十进制位数（数量级）分桶，
// <=0 单独成桶。同一张页面在不同请求间的长度差异只有几个字节（Host 回显、
// 时间戳），位数分桶足以判「同一模板 vs 完全不同的页面」；999 与 1000 这类
// 桶边界两侧的误判方向都是放行，符合宁可漏杀的红线。
func LengthBucket(n int) int {
	if n <= 0 {
		return 0
	}
	b := 1
	for n >= 10 {
		n /= 10
		b++
	}
	return b
}

// titleRe 与 fingerprint 的标题提取同一条正则。
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle 从基线响应体提取 <title> 文本。刻意不做 charset 解码：GBK
// 默认页的基线标题会是乱码、与解码后的候选标题必然不同，判定方向是放行（漏杀）。
func extractTitle(body string) string {
	if m := titleRe.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// normalizeTitle 标题归一化：压连续空白 + 小写。同一默认页在不同请求间的空白
// 差异不参与比较；误杀方向另有长度分桶与 favicon 双保险。
func normalizeTitle(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// FormKey 返回观测的「形态」键：状态码 + 长度桶 + 归一化标题，聚类兜底用，
// 与基线测量的三要素同口径。
func FormKey(r Response) string {
	return fmt.Sprintf("%d|%d|%s", r.StatusCode, LengthBucket(r.BodyLen), normalizeTitle(r.Title))
}

// LooksLikeBaseline 判定候选站点是否应按 catch-all 默认页剔除。剔除要求全部满足：
//   - 标题一致（归一化后相等；有独立标题 = 业务站点，放行）；
//   - 长度同桶（LengthBucket 相等）；
//   - 无业务特征：候选 favicon 与基线不同即业务站点。基线探针按成本红线不带
//     favicon 请求（每 IP 预算全部留给两次页面采样），基线 favicon 恒为空，
//     因此凡带自有 favicon 的候选一律放行，带图标的最小拦截交给聚类兜底；
//   - 证据下限：标题或 favicon 至少一样非空。双方全空时无法证明是同一张页面
//     （两个无标题无图标的页面长度轻易同桶），放行。
func LooksLikeBaseline(baseline, cand Response) bool {
	bt, ct := normalizeTitle(baseline.Title), normalizeTitle(cand.Title)
	if bt != ct {
		return false
	}
	if LengthBucket(cand.BodyLen) != LengthBucket(baseline.BodyLen) {
		return false
	}
	if cand.FaviconMMH3 != baseline.FaviconMMH3 {
		return false
	}
	return bt != "" || (baseline.FaviconMMH3 != "" && cand.FaviconMMH3 != "")
}

// Candidate 是聚类兜底的一个候选站点。
type Candidate struct {
	URL      string // 仅用于结果可读，不参与形态判定
	Response Response
}

// MarkClusters 聚类兜底打标：同一批候选（调用方按 IP 聚好的组）中，同形态
// （FormKey 相同）数量达到 ClusterMinGroup 的组整组标记。只打标不剔除——这是
// 基线探针漏网时的统计兜底，宁可错标待复核，不可误删业务站点。返回与 cands
// 等长的打标数组。
func MarkClusters(cands []Candidate) []bool {
	marked := make([]bool, len(cands))
	groups := map[string][]int{}
	for i, c := range cands {
		k := FormKey(c.Response)
		groups[k] = append(groups[k], i)
	}
	for _, idxs := range groups {
		if len(idxs) < ClusterMinGroup {
			continue
		}
		for _, i := range idxs {
			marked[i] = true
		}
	}
	return marked
}

// Prober 发随机 Host 基线探针。复用调用方的 *http.Client——流水线把 HTTP 指纹
// 阶段同一个客户端传进来，超时/代理出口/安全拨号策略全部继承，不另起一套。
type Prober struct {
	Client *http.Client
	// Timeout 单个探针的超时上限；<=0 按 defaultProbeTimeout。
	Timeout time.Duration
}

// New 用给定客户端构造 Prober；client 为 nil 时 Baseline 恒失败（放弃去噪）。
func New(client *http.Client) *Prober {
	return &Prober{Client: client}
}

// Baseline 对 scheme://ip:port 发 MaxBaselineProbes 个随机 Host 探针取默认后端
// 基线。两次观测同形（状态码/归一化标题/长度桶一致）才认基线成立；任何失败
// 返回 ok=false，调用方应放弃去噪、放行全部候选。
func (p *Prober) Baseline(ctx context.Context, scheme, ip string, port int) (Response, bool) {
	if p == nil || p.Client == nil || (scheme != "http" && scheme != "https") ||
		ip == "" || port <= 0 || ctx.Err() != nil {
		return Response{}, false
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	var first Response
	for i := 0; i < MaxBaselineProbes; i++ {
		resp, ok := p.probeOnce(ctx, scheme, ip, port, timeout)
		if !ok {
			return Response{}, false
		}
		if i == 0 {
			first = resp
			continue
		}
		if !sameShape(first, resp) {
			// 源站对随机 Host 的响应不稳定（动态内容/轮换页），基线无法定义。
			return Response{}, false
		}
	}
	return first, true
}

// sameShape 两次基线观测是否同形：与 LooksLikeBaseline 的相似口径一致
// （状态码/归一化标题/长度桶）；favicon 不参与——探针按成本红线不请求 favicon。
func sameShape(a, b Response) bool {
	return a.StatusCode == b.StatusCode &&
		normalizeTitle(a.Title) == normalizeTitle(b.Title) &&
		LengthBucket(a.BodyLen) == LengthBucket(b.BodyLen)
}

// probeOnce 发一次随机 Host 探针：GET scheme://ip:port/，Host 头替换为随机
// 主机名，按 Host 路由的源站会把它送进默认后端。非 200 响应照常记录（404/403
// 兜底页也是默认后端形态）；传输错误/超时返回 ok=false。
func (p *Prober) probeOnce(ctx context.Context, scheme, ip string, port int, timeout time.Duration) (Response, bool) {
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet,
		scheme+"://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/", nil)
	if err != nil {
		return Response{}, false
	}
	host := randomHost()
	if host == "" {
		return Response{}, false // crypto/rand 失败视同探针失败
	}
	req.Host = host
	req.Header.Set("User-Agent", probeUserAgent)
	req.Header.Set("Accept", probeAccept)
	resp, err := p.Client.Do(req)
	if err != nil {
		return Response{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	return Response{
		StatusCode: resp.StatusCode,
		BodyLen:    len(body),
		Title:      extractTitle(string(body)),
	}, true
}

// randomHost 生成固定长度随机 Host：<12 位 hex>.invalid。固定长度让「默认页
// 回显 Host」类站点的基线长度不抖动；crypto/rand 失败返回空串（调用方视为
// 探针失败，放弃去噪）。
func randomHost() string {
	b := make([]byte, randomHostLabelLen/2)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b) + randomHostSuffix
}
