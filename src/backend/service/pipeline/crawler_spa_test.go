package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// SetRate 的 katana 并发钳制：任务模板会把模块并发压到 1，
// 原样透传就是 -c 1 单目标全串行。
func TestCrawlerSetRateClampsKatanaConcurrency(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{in: 1, want: 3}, // 任务模板的典型值，不允许 -c 1
		{in: 2, want: 3}, // 下限钳制
		{in: 3, want: 3}, // 边界
		{in: 8, want: 8}, // 正常值原样
		{in: 10, want: 10},
		{in: 50, want: 10}, // 上限钳制
	}
	for _, c := range cases {
		m := NewCrawlerModule(context.Background(), nil, 4, true)
		m.SetRate(10, c.in)
		if m.katanaScanner.Concurrency != c.want {
			t.Fatalf("SetRate(10,%d): katana 并发 = %d, 期望 %d", c.in, m.katanaScanner.Concurrency, c.want)
		}
		if m.concurrency != c.in {
			t.Fatalf("SetRate(10,%d): 模块并发应原样保留 %d, got %d", c.in, c.in, m.concurrency)
		}
		if m.katanaScanner.RateLimit != 10 {
			t.Fatalf("RateLimit 应跟随任务级速率, got %d", m.katanaScanner.RateLimit)
		}
	}
}

// looksLikeSPA 的判定口径：框架挂载点 / 运行时全局变量 / 小首页+hash JS。
func TestLooksLikeSPA(t *testing.T) {
	cases := []struct {
		name string
		body string
		code int
		want bool
	}{
		{name: "react-root", body: `<div id="root"></div>`, code: 200, want: true},
		{name: "vue-app", body: `<DIV ID="app">`[0:0] + `<div id="app"></div>`, code: 200, want: true},
		{name: "next-data", body: `window.__NEXT_DATA__={}`, code: 200, want: true},
		{name: "ng-version", body: `<div ng-version="17.0.0">`, code: 200, want: true},
		{name: "small-with-hashjs", body: `<!DOCTYPE html><html><head><script src="/assets/index-Bq3Ft1Wn.js"></script></head><body></body></html>`, code: 200, want: true},
		{name: "small-hash-js-case", body: `<script src="/static/chunk.ABCDEF12.js" defer></script>`, code: 200, want: true},
		{name: "plain-server-page", body: fmt.Sprintf("<html><body>%s</body></html>", strings.Repeat("x", 4096)), code: 200, want: false},
		{name: "small-no-js", body: `<html><body>hello</body></html>`, code: 200, want: false},
		{name: "server-error", body: "oops", code: 500, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.code)
				w.Write([]byte(c.body))
			}))
			defer srv.Close()
			if got := looksLikeSPA(context.Background(), srv.URL); got != c.want {
				t.Fatalf("looksLikeSPA(%s) = %v, 期望 %v", c.name, got, c.want)
			}
		})
	}

	// 探测失败（连接拒绝）按非 SPA 处理，不 panic
	if looksLikeSPA(context.Background(), "http://127.0.0.1:1/nope") {
		t.Fatal("探测失败应按非 SPA 处理")
	}
}

// headless 分流：SPA 目标走浅拷贝 scanner 且 Headless=true，
// 非 SPA 目标沿用共享 scanner 且保持 false。
func TestCrawlTargetHeadlessRouting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><div id="app"></div><script src="/apphash123.js"></script></body></html>`))
	}))
	defer srv.Close()

	m := NewCrawlerModule(context.Background(), nil, 1, true)
	if !headlessBrowserAvailable() {
		t.Skip("环境无系统 Chrome/Chromium，分流无法验证")
	}
	m.crawlTarget(AssetHttp{URL: srv.URL, Host: "127.0.0.1"})
	if m.katanaScanner.Headless {
		t.Fatal("共享 scanner 不应被 per-target 的 headless 开关污染")
	}
	_ = webscan.NewKatanaScanner
}
