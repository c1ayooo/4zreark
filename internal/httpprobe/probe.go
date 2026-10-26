package httpprobe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Request 是一次 HTTP 探测请求（报告与差分探测共用的最小形态）。
type Request struct {
	Label             string            `json:"label,omitempty"`
	Method            string            `json:"method,omitempty"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers,omitempty"`
	Body              string            `json:"body,omitempty"`
	Proxy             string            `json:"proxy,omitempty"`
	TimeoutSeconds    int               `json:"timeout_seconds,omitempty"`
	RandomFingerprint string            `json:"random_fingerprint,omitempty"`
}

// Result 是一次探测的结果。
type Result struct {
	StatusCode   int         `json:"status_code"`
	StatusText   string      `json:"status_text"`
	DurationMS   int64       `json:"duration_ms"`
	RespHeaders  http.Header `json:"-"`
	RespBody     string      `json:"resp_body"`
	RequestText  string      `json:"request_text"`
	ResponseText string      `json:"response_text"`
	Transcript   string      `json:"transcript"`
	FinalURL     string      `json:"final_url,omitempty"`
}

// DoRequest 执行一次探测并生成完整报文。调用方负责 URL 已通过 scope 校验。
func DoRequest(ctx context.Context, req Request) (*Result, error) {
	if strings.TrimSpace(req.URL) == "" {
		return nil, fmt.Errorf("URL 不能为空")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if req.Body != "" {
		body = bytes.NewBufferString(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}
	if req.RandomFingerprint != "" && hreq.Header.Get("User-Agent") == "" {
		hreq.Header.Set("User-Agent", req.RandomFingerprint)
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}
	if req.Proxy != "" {
		if pu, perr := url.Parse(req.Proxy); perr == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	timeout := 15 * time.Second
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	start := time.Now()
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	res := &Result{
		StatusCode:  resp.StatusCode,
		StatusText:  resp.Status,
		DurationMS:  time.Since(start).Milliseconds(),
		RespHeaders: resp.Header,
		RespBody:    string(raw),
		FinalURL:    resp.Request.URL.String(),
	}
	if dump, derr := httputil.DumpRequestOut(hreq, true); derr == nil {
		res.RequestText = string(dump)
	}
	if dump, derr := httputil.DumpResponse(resp, true); derr == nil {
		res.ResponseText = string(dump)
	}
	if res.RequestText != "" || res.ResponseText != "" {
		res.Transcript = RequestMarker + "\n" + res.RequestText + "\n" + ResponseMarker + "\n" + res.ResponseText
	}
	return res, nil
}
