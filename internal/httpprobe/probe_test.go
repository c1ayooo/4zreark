package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "1" {
			http.Error(w, "missing header", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Reply", "ok")
		_, _ = w.Write([]byte("hello probe"))
	}))
	defer srv.Close()

	res, err := DoRequest(context.Background(), Request{
		URL: srv.URL, Headers: map[string]string{"X-Test": "1"}, TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if res.StatusCode != 200 || res.RespBody != "hello probe" {
		t.Fatalf("响应不符: %d %q", res.StatusCode, res.RespBody)
	}
	if res.RespHeaders.Get("X-Reply") != "ok" {
		t.Fatalf("响应头未保留: %v", res.RespHeaders)
	}
	if !strings.Contains(res.Transcript, RequestMarker) || !strings.Contains(res.Transcript, ResponseMarker) {
		t.Fatalf("报文缺少标记: %q", res.Transcript)
	}
	if !strings.Contains(res.RequestText, "X-Test: 1") {
		t.Fatalf("请求报文缺少自定义头: %q", res.RequestText)
	}
}

func TestDoRequestValidation(t *testing.T) {
	if _, err := DoRequest(context.Background(), Request{}); err == nil {
		t.Fatal("空 URL 应报错")
	}
	if _, err := DoRequest(context.Background(), Request{URL: "://bad"}); err == nil {
		t.Fatal("非法 URL 应报错")
	}
}
