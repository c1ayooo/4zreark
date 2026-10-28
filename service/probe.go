package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/extractor"
	"github.com/c1ayooo/4zreark/internal/safehttp"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/useragent"
)

// 探测结果分类。分类决定「算不算失联」：
// 只有明确连不上（DNS 无解、TCP 拒绝、TLS 握手失败、超时）才计入失败次数；
// FakeIP 与「公网域名解析到私网地址」属于环境噪声，记一笔流水但不算失败。
type ProbeOutcome string

const (
	ProbeReachable    ProbeOutcome = "reachable"    // 收到 HTTP 响应（403/404/500 都算）
	ProbeDNSFail      ProbeOutcome = "dns_fail"     // 域名解析不出来
	ProbeConnFail     ProbeOutcome = "conn_fail"    // TCP 连不上（拒绝/不可达）
	ProbeTLSFail      ProbeOutcome = "tls_fail"     // TLS 握手失败
	ProbeTimeout      ProbeOutcome = "timeout"      // 超时
	ProbeInconclusive ProbeOutcome = "inconclusive" // 环境噪声：FakeIP / 私网回落
)

// ProbeResult 是一次探测的结果。
type ProbeResult struct {
	Outcome    ProbeOutcome `json:"outcome"`
	ReasonCode string       `json:"reason_code"`
	StatusCode int          `json:"status_code"`
	Addr       string       `json:"addr"`
	ElapsedMS  int64        `json:"elapsed_ms"`
	Detail     string       `json:"detail"`

	// 关系层用的三个观测值（都来自同一次探测，不额外发包）：
	//   FinalURL   跟随跳转后的最终 URL（redirect 关系）
	//   CertSHA256 服务端证书 DER 的 SHA-256（same_cert 关系）
	FinalURL   string `json:"final_url,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`

	// 指纹匹配用的快照，不进 API 响应（正文可能几百 KB）
	Title   string            `json:"title,omitempty"`
	Server  string            `json:"server,omitempty"`
	Body    string            `json:"-"`
	Headers map[string]string `json:"-"`
	// ICP 是从正文提取的工信部备案/许可证号（快照字段，不进 API 响应）。
	ICP []string `json:"-"`
}

// Reachable 表示这个结果能证明「站点还活着」。
func (r ProbeResult) Reachable() bool { return r.Outcome == ProbeReachable }

// Inconclusive 表示这个结果既不能证明活、也不能证明死。
func (r ProbeResult) Inconclusive() bool { return r.Outcome == ProbeInconclusive }

// 探测使用的默认参数。超时给 8 秒：国内站点首次 TLS 握手常见 3–5 秒。
const (
	probeTimeout = 8 * time.Second
	// 指纹只看头部特征，正文读 256KB 足够，避免被大文件拖住
	probeBodyLimit = 256 << 10
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// resolveIPAddr 抽成变量：单测里换掉它就能模拟 FakeIP / 私网回落，不用真去改 DNS。
var resolveIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// fakeIPNet 是 Clash / Surge 一类代理的 fake-ip 段（198.18.0.0/15）。
// 命中说明本地 DNS 被代理接管，连不上不能算资产失联。
var fakeIPNet = &net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}

// probeClient 复用连接、不校验证书（扫描器惯例）、最多 5 跳重定向。
var probeClient = &http.Client{
	Timeout: probeTimeout,
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     false,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   6 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		// 审计 M3：连接级 SSRF 校验（ModeScan：内网资产合法，loopback/云元数据禁）
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
			// KeepAlive 经 safehttp 控制版本保留
			Control: safehttp.NewDialer(safehttp.ModeScan, 5*time.Second).Control,
		}).DialContext,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// ProbeEndpoint 探测一个入口（host + port + scheme）。
// 不做端口发现，只回答「这个入口现在通不通」。
func ProbeEndpoint(ctx context.Context, host string, port int, scheme string) ProbeResult {
	start := time.Now()
	res := ProbeResult{}

	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	if port <= 0 {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}

	// 1) 解析：裸 IP 直接用，域名走 Lookup
	addr := strings.TrimSpace(host)
	if net.ParseIP(addr) == nil {
		ips, err := resolveIPAddr(ctx, host)
		if err != nil {
			res.ElapsedMS = time.Since(start).Milliseconds()
			res.Outcome = ProbeDNSFail
			res.ReasonCode = "dns_fail"
			if isTimeoutErr(err) {
				res.Outcome, res.ReasonCode = ProbeTimeout, "dns_timeout"
			}
			res.Detail = err.Error()
			return res
		}
		if len(ips) == 0 {
			res.ElapsedMS = time.Since(start).Milliseconds()
			res.Outcome, res.ReasonCode = ProbeDNSFail, "dns_empty"
			return res
		}
		addr = ips[0].IP.String()
		// 公网域名解析进 fake-ip 段 → 本地代理接管，判不出真假
		if fakeIPNet.Contains(ips[0].IP) {
			res.ElapsedMS = time.Since(start).Milliseconds()
			res.Outcome, res.ReasonCode = ProbeInconclusive, "fake_ip"
			res.Addr = addr
			res.Detail = "域名解析到 fake-ip 段（198.18.0.0/15），本地代理接管中"
			return res
		}
		// 公网域名解析到私网/环回 → 污染或内部专用，同样不判死
		if isPrivateIP(ips[0].IP) {
			res.ElapsedMS = time.Since(start).Milliseconds()
			res.Outcome, res.ReasonCode = ProbeInconclusive, "private_addr"
			res.Addr = addr
			res.Detail = "公网域名解析到私网地址"
			return res
		}
	}
	res.Addr = addr

	// 2) TCP 预连：把「拒绝 / 不可达 / 超时」区分开，比 http 的报错更好归类
	hostPort := net.JoinHostPort(addr, fmt.Sprint(port))
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", hostPort)
	if err != nil {
		res.ElapsedMS = time.Since(start).Milliseconds()
		res.ReasonCode = "conn_fail"
		res.Outcome = ProbeConnFail
		if isTimeoutErr(err) {
			res.Outcome, res.ReasonCode = ProbeTimeout, "tcp_timeout"
		}
		res.Detail = err.Error()
		return res
	}
	_ = conn.Close()

	// 3) HTTP：拿到任意状态码都算连通（403/404/500 也算，这是 v2 §8 的明确口径）
	url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprint(port)))
	resp, body, err := fetchProbeHTTP(ctx, url, useragent.Pick())
	res.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Outcome, res.ReasonCode = ProbeConnFail, "http_error"
		if isTimeoutErr(err) {
			res.Outcome, res.ReasonCode = ProbeTimeout, "http_timeout"
		} else if isTLSErr(err) {
			res.Outcome, res.ReasonCode = ProbeTLSFail, "tls_fail"
		}
		res.Detail = err.Error()
		return res
	}

	// 桌面 UA 被 WAF 挡掉时，用手机 UA 再试一次；手机站通常是另一套规则。
	if shouldRetryWithMobile(resp.StatusCode) {
		resp2, body2, err2 := fetchProbeHTTP(ctx, url, useragent.PickMobile())
		res.ElapsedMS = time.Since(start).Milliseconds()
		if err2 == nil && (resp2.StatusCode < 400 || resp2.StatusCode < resp.StatusCode) {
			resp, body = resp2, body2
			res.Detail = "mobile_ua"
		}
	}

	// 采集指纹快照：标题、Server、响应头、正文前 256KB
	res.Body = string(body)
	res.Title = extractTitle(res.Body)
	res.Server = resp.Header.Get("Server")
	res.Headers = flattenHeaders(resp.Header)
	// 备案号：正文页脚几乎必有，是资产归属最强的外部证据之一。
	res.ICP = extractor.ExtractICPNumbers(res.Body)
	// 关系层观测值：最终 URL 与证书指纹。都取自本次响应，不额外发包。
	if resp.Request != nil && resp.Request.URL != nil {
		res.FinalURL = resp.Request.URL.String()
	}
	res.CertSHA256 = certFingerprint(resp)

	res.Outcome = ProbeReachable
	res.StatusCode = resp.StatusCode
	res.ReasonCode = "http_ok"
	if resp.StatusCode >= 400 {
		// 有响应 = 活着，但把 4xx/5xx 单独标出来，前端能区分「活着但异常」
		res.ReasonCode = "http_error"
	}
	return res
}

func shouldRetryWithMobile(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotAcceptable,
		http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	}
	return false
}

// certFingerprint 取响应 TLS 握手里的叶子证书，返回 DER 的 SHA-256 十六进制。
// 非 HTTPS 或拿不到连接状态时返回空串。
//
// 为什么用证书 DER 而不是序列号：同一张证书的序列号在不同 CSR/重签后会变，
// 而「同一张证书」正是 same_cert 关系要表达的意思。
func certFingerprint(resp *http.Response) string {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:])
}

func fetchProbeHTTP(ctx context.Context, url, ua string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	resp, err := probeClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit))
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

// extractTitle 从 HTML 里取 <title>，压平空白并截断到 200 字符。
func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.Join(strings.Fields(m[1]), " ")
	if len([]rune(t)) > 200 {
		t = string([]rune(t)[:200])
	}
	return t
}

// flattenHeaders 压成小写 key → 逗号拼接的值，方便按名字查。
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[strings.ToLower(k)] = strings.Join(vs, ", ")
	}
	return out
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func isTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func isTLSErr(err error) bool {
	var (
		recErr tls.RecordHeaderError
		verErr *tls.CertificateVerificationError
	)
	if errors.As(err, &recErr) || errors.As(err, &verErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls") || strings.Contains(msg, "x509") ||
		strings.Contains(msg, "certificate")
}
