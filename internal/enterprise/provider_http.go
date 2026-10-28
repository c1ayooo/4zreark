package enterprise

import (
	"github.com/c1ayooo/4zreark/internal/safehttp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// webClient 各企业数据源 adapter 共享的出站 HTTP 客户端：
// 统一浏览器 UA/超时/TLS/代理语义；Cookie 或 Token 由各 adapter 注入 headers。
type webClient struct {
	base    string
	http    *http.Client
	headers map[string]string
}

const webBodyLimit = 4 << 20 // 单响应上限 4MB

func newWebClient(base, proxy string, timeout time.Duration) (*webClient, error) {
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("数据源地址无效: %w", err)
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
	return &webClient{
		base: strings.TrimRight(base, "/"),
		// 审计 M3：数据源站点是固定公网上游，连接级校验（scan 档）；
		// 走代理时校验由代理出口承接（Control 看到的是代理地址）。
		http: &http.Client{Timeout: timeout, Transport: safehttp.WithSafeControl(transport, timeout)},
		headers: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
			"Accept":          "application/json, text/plain, */*",
			"Accept-Language": "zh-CN,zh;q=0.9",
		},
	}, nil
}

// do 发起请求并返回响应体（限长）。isJSON 时设置 Content-Type。
func (w *webClient) do(ctx context.Context, method, path string, body io.Reader, isJSON bool, extra map[string]string) (string, error) {
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
	resp, err := w.http.Do(req)
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

func (w *webClient) getJSON(ctx context.Context, path string, extra map[string]string) (string, error) {
	return w.do(ctx, http.MethodGet, path, nil, false, extra)
}

func (w *webClient) postJSON(ctx context.Context, path, body string, extra map[string]string) (string, error) {
	return w.do(ctx, http.MethodPost, path, strings.NewReader(body), true, extra)
}

// urlQueryEscape 查询串转义（adapter 内共用）。
func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
