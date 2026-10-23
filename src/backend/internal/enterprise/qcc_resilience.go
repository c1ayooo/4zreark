// Package enterprise 企查查采集风控接线。
// @file      : qcc_resilience.go
// @author    : c1ay
// @time      : 2026/10/23
// -------------------------------------------
// 企查查（qcc）的纵深熔断：per-host 熔断器 + 代理池（复用 internal/resilience）。
//
// 企查查风控极敏感：412/405/403 意味着出口 IP 已被限流，继续硬撞只会延长封禁。
// 这里在 qccProvider.get 的链路上加三道闸：
//  1. 熔断器：开闸期间直接拒绝并给出「建议 N 秒后重试」；
//  2. 代理池：proxyURL 支持逗号/换行分隔多代理，轮转使用；被封出口自动拉黑换道，
//     全部被封时回退直连并由熔断器节流；
//  3. 结果回填：412/405/403 → RecordBlocked + blocked（快速开闸）；其他错误 →
//     RecordFailure + error；成功 → RecordSuccess + ok。
//
// 本文件独立成篇的原因：webClient（provider_http.go）是各数据源共享的公共路径，
// 不宜为 qcc 单独改动；这里以包内增补方法（doVia）的方式扩展，行为零侵入。
package enterprise

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/resilience"
)

// qccGuard 企查查采集风控守卫：熔断器集合 + 出口代理池 + 按出口隔离的 HTTP 客户端。
type qccGuard struct {
	breakers *resilience.BreakerSet
	pool     *resilience.ProxyPool

	mu      sync.Mutex
	clients map[string]*http.Client // 按出口串（""=直连）惰性建连
	timeout time.Duration
}

// newQccGuard 构造守卫；proxyURL 支持逗号/换行分隔多代理，空串 = 直连单车道。
func newQccGuard(proxyURL string) *qccGuard {
	return &qccGuard{
		breakers: resilience.NewBreakerSet(),
		pool:     resilience.NewProxyPool(proxyURL),
		clients:  map[string]*http.Client{},
		timeout:  20 * time.Second, // 对齐 NewQccProvider 的 newWebClient 超时
	}
}

// get 带限速与风控熔断的 GET：qccProvider.get 的实现本体。
// c 仅用于复用其 base/headers 配置；实际出站走守卫自有的按出口客户端。
func (g *qccGuard) get(ctx context.Context, c *webClient, path string) (string, error) {
	host := hostOfURL(c.base)
	bk := g.breakers.Get(host)
	if ok, retryAfter := bk.Allow(); !ok {
		// 熔断打开：沿用既有中文风控文案风格，附建议等待秒数。
		return "", fmt.Errorf("企查查风控拦截（熔断保护中）：出口 IP 已被限流，%w",
			&resilience.CircuitOpenError{Host: host, RetryAfter: retryAfter})
	}

	qccThrottle() // 全局 2.5s 串行限速（见 qcc.go），所有出口共用同一节拍

	proxy := g.pool.Pick()
	body, err := c.doVia(ctx, g.clientFor(proxy), "GET", path, nil, false, nil)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "412") || strings.Contains(msg, "405") || strings.Contains(msg, "403") {
			// 明确的风控拦截：快速通道开闸 + 拉黑当前出口。
			bk.RecordBlocked()
			g.pool.Report(proxy, resilience.OutcomeBlocked)
			return "", fmt.Errorf("企查查风控拦截（%s）：出口 IP 已被限流，请降低采集频率、等待解封或配置代理", msg)
		}
		bk.RecordFailure()
		g.pool.Report(proxy, resilience.OutcomeError)
		return "", err
	}
	bk.RecordSuccess()
	g.pool.Report(proxy, resilience.OutcomeOK)
	return body, nil
}

// clientFor 返回绑定指定出口的 HTTP 客户端（惰性创建并缓存）。
// 代理语义对齐 newWebClient：http/https/socks5 之外的串一律直连。
func (g *qccGuard) clientFor(proxy string) *http.Client {
	g.mu.Lock()
	defer g.mu.Unlock()
	if hc, ok := g.clients[proxy]; ok {
		return hc
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	if pu := strings.TrimSpace(proxy); pu != "" {
		if u, err := url.Parse(pu); err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "socks5") {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	hc := &http.Client{Timeout: g.timeout, Transport: transport}
	g.clients[proxy] = hc
	return hc
}

// doVia 与 webClient.do 语义一致（header 注入/JSON/限长/状态码翻译），
// 但走调用方给定的 HTTP 客户端，用于多出口轮转。独立成方法是为了不改
// provider_http.go 的公共路径（aqc/tyc 等不受影响）。
func (w *webClient) doVia(ctx context.Context, hc *http.Client, method, path string, body io.Reader, isJSON bool, extra map[string]string) (string, error) {
	if !strings.HasPrefix(path, "http") {
		path = w.base + path
	}
	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return "", err
	}
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	if isJSON {
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, webBodyLimit))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("上游状态码 %d（会话可能过期）", resp.StatusCode)
	}
	return string(data), nil
}

// hostOfURL 从 base URL 提取 host（熔断器粒度）；解析失败时原样返回。
func hostOfURL(base string) string {
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Host
	}
	return base
}
