package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
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
}

// Reachable 表示这个结果能证明「站点还活着」。
func (r ProbeResult) Reachable() bool { return r.Outcome == ProbeReachable }

// Inconclusive 表示这个结果既不能证明活、也不能证明死。
func (r ProbeResult) Inconclusive() bool { return r.Outcome == ProbeInconclusive }

// 探测使用的默认参数。超时给 8 秒：国内站点首次 TLS 握手常见 3–5 秒。
const (
	probeTimeout = 8 * time.Second
	probeUA      = "Mozilla/5.0 (compatible; 4zreark-probe/1.0)"
)

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
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.ElapsedMS = time.Since(start).Milliseconds()
		res.Outcome, res.ReasonCode = ProbeConnFail, "bad_url"
		res.Detail = err.Error()
		return res
	}
	req.Header.Set("User-Agent", probeUA)
	req.Header.Set("Accept", "*/*")

	resp, err := probeClient.Do(req)
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
	defer resp.Body.Close()

	res.Outcome = ProbeReachable
	res.StatusCode = resp.StatusCode
	res.ReasonCode = "http_ok"
	if resp.StatusCode >= 400 {
		// 有响应 = 活着，但把 4xx/5xx 单独标出来，前端能区分「活着但异常」
		res.ReasonCode = "http_error"
	}
	return res
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
