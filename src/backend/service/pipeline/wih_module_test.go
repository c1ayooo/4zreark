package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fastWihCfg 测试用配置：限速/预算收紧，保证用例快速跑完。
func fastWihCfg() WihConfig {
	cfg := DefaultWihConfig()
	cfg.Probe.RateDelay = time.Millisecond
	cfg.Probe.PerSiteBudget = 10 * time.Second
	cfg.Probe.PerRequestTimeout = 2 * time.Second
	return cfg
}

// newWihTestServer 起一个首页带 fetch/字面量接口的测试站。
func newWihTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// 首页：fetch("/api/users") 与字面量 '/api/config'
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body><script>
			fetch("/api/users");
			var ep = '/api/config';
		</script></body></html>`)
	})
	// JS 文件：UrlResult 指向它时也应被处理
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `axios.get("/api/fromjs");`)
	})
	api := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}
	mux.HandleFunc("/api/users", api)
	mux.HandleFunc("/api/config", api)
	mux.HandleFunc("/api/fromjs", api)
	mux.HandleFunc("/page.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<script>fetch("/api/users")</script>`)
	})
	return httptest.NewServer(mux)
}

// drainAll 读完 out 直到关闭，返回收集到的数据。
func drainWihOut(t *testing.T, out chan any) []interface{} {
	t.Helper()
	var got []interface{}
	for v := range out {
		got = append(got, v)
	}
	return got
}

// 用例 1：流式喂入 AssetHttp / UrlResult / 未知类型，断言透传 + WihResult 产出
func TestWihProbeModuleStream(t *testing.T) {
	srv := newWihTestServer(t)
	defer srv.Close()

	in := make(chan any, 8)
	out := make(chan any, 64)
	m := NewWihProbeModule(context.Background(), in, out, fastWihCfg())
	m.Start()

	in <- AssetHttp{URL: srv.URL}
	in <- UrlResult{Output: srv.URL + "/static/app.js", Source: "katana"}
	in <- PortAlive{Host: "unknown-type-host"} // 未知类型：只透传不处理
	close(in)
	m.Wait()

	got := drainWihOut(t, out)

	// 三个输入都应透传
	var sawAsset, sawURL, sawUnknown bool
	var results []WihResult
	for _, v := range got {
		switch d := v.(type) {
		case AssetHttp:
			sawAsset = d.URL == srv.URL
		case UrlResult:
			sawURL = d.Output == srv.URL+"/static/app.js"
		case PortAlive:
			sawUnknown = d.Host == "unknown-type-host"
		case WihResult:
			results = append(results, d)
		}
	}
	if !sawAsset || !sawURL || !sawUnknown {
		t.Fatalf("三个输入都应原样透传，got %+v", got)
	}

	// 两个可处理的 URL 各产出一条 WihResult
	if len(results) != 2 {
		t.Fatalf("应产出 2 条 WihResult，got %d: %+v", len(results), got)
	}
	byTarget := map[string]WihResult{}
	for _, r := range results {
		byTarget[r.Target] = r
	}
	homeRes, ok := byTarget[srv.URL]
	if !ok {
		t.Fatalf("首页应产出 WihResult，targets: %+v", byTarget)
	}
	var sawUsers, sawConfig bool
	for _, ep := range homeRes.Endpoints {
		if strings.HasSuffix(ep.URL, "/api/users") && ep.Verified && ep.StatusCode == 200 {
			sawUsers = true
		}
		if strings.HasSuffix(ep.URL, "/api/config") && ep.Verified {
			sawConfig = true
		}
	}
	if !sawUsers || !sawConfig {
		t.Fatalf("首页的 /api/users 与 /api/config 都应探测为 verified，got %+v", homeRes.Endpoints)
	}

	jsRes, ok := byTarget[srv.URL+"/static/app.js"]
	if !ok {
		t.Fatalf("JS 文件应产出 WihResult，targets: %+v", byTarget)
	}
	foundJS := false
	for _, ep := range jsRes.Endpoints {
		if strings.HasSuffix(ep.URL, "/api/fromjs") && ep.Verified {
			foundJS = true
		}
	}
	if !foundJS {
		t.Fatalf("JS 里的 /api/fromjs 应探测为 verified，got %+v", jsRes.Endpoints)
	}
}

// 用例 2：非 HTML/JS 的 Content-Type 不处理；重复 URL 只处理一次
func TestWihProbeModuleContentTypeGate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/img.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "binary")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	in := make(chan any, 4)
	out := make(chan any, 16)
	m := NewWihProbeModule(context.Background(), in, out, fastWihCfg())
	m.Start()

	in <- AssetHttp{URL: srv.URL + "/img.png"}
	in <- AssetHttp{URL: srv.URL + "/img.png"} // 去重：同 URL 不重复处理
	close(in)
	m.Wait()

	got := drainWihOut(t, out)
	if len(got) != 2 {
		t.Fatalf("两条输入都应透传，got %+v", got)
	}
	for _, v := range got {
		if _, isWih := v.(WihResult); isWih {
			t.Fatalf("image/png 不应产出 WihResult，got %+v", got)
		}
	}
}

// 用例 3：SetEnabled(false) 后纯透传，不产出 WihResult
func TestWihProbeModuleDisabled(t *testing.T) {
	srv := newWihTestServer(t)
	defer srv.Close()

	in := make(chan any, 4)
	out := make(chan any, 16)
	cfg := fastWihCfg()
	cfg.Enabled = false
	m := NewWihProbeModule(context.Background(), in, out, cfg)
	m.Start()

	in <- AssetHttp{URL: srv.URL}
	close(in)
	m.Wait()

	got := drainWihOut(t, out)
	if len(got) != 1 {
		t.Fatalf("禁用时应只有透传数据，got %+v", got)
	}
	if _, isWih := got[0].(WihResult); isWih {
		t.Fatalf("禁用时不应产出 WihResult，got %+v", got)
	}
	if asset, ok := got[0].(AssetHttp); !ok || asset.URL != srv.URL {
		t.Fatalf("禁用时应原样透传 AssetHttp，got %+v", got[0])
	}
}

// 用例 4：构造函数通道为 any 别名兼容，out 关闭后 Wait 返回且不 panic
func TestWihProbeModuleOutClosed(t *testing.T) {
	srv := newWihTestServer(t)
	defer srv.Close()

	var in chan any = make(chan any, 2)
	var out chan interface{} = make(chan interface{}, 16)
	m := NewWihProbeModule(context.Background(), in, out, fastWihCfg())
	m.Start()

	in <- AssetHttp{URL: srv.URL}
	close(in)
	m.Wait()

	// Wait 返回后 out 已关闭；注意关闭通道里的缓冲值依然可读，先 range 排空
	var drained []interface{}
	sawAsset := false
	for v := range out {
		drained = append(drained, v)
		if a, isAsset := v.(AssetHttp); isAsset && a.URL == srv.URL {
			sawAsset = true
		}
	}
	if !sawAsset {
		t.Fatalf("应原样透传 AssetHttp，got %+v", drained)
	}
	// 排空后再次读取应立即返回 ok=false（通道确已关闭）
	if v, ok := <-out; ok {
		t.Fatalf("out 应已关闭，却读到 %+v", v)
	}
}
