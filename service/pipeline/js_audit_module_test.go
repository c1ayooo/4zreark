package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/scope"
)

func TestLooksLikeJS(t *testing.T) {
	cases := []struct {
		url, ct string
		want    bool
	}{
		{"https://a.com/static/app.js", "", true},
		{"https://a.com/main.js?v=1", "", true},
		{"https://a.com/x.mjs", "", true},
		{"https://a.com/api/user", "", false},
		{"https://a.com/index.html", "", false},
		{"https://a.com/any", "application/javascript", true},
		{"https://a.com/any", "text/javascript; charset=utf-8", true},
		{"https://a.com/any", "application/json", false},
	}
	for _, c := range cases {
		if got := looksLikeJS(c.url, c.ct); got != c.want {
			t.Errorf("looksLikeJS(%q,%q)=%v want %v", c.url, c.ct, got, c.want)
		}
	}
}

func TestExtractJSURL(t *testing.T) {
	u, ct := extractJSURL(UrlResult{Output: "https://a.com/app.js", ContentType: "application/javascript"})
	if u != "https://a.com/app.js" || ct != "application/javascript" {
		t.Fatalf("UrlResult 提取失败: %q %q", u, ct)
	}
	u, ct = extractJSURL(AssetHttp{URL: "https://a.com/x.js"})
	if u != "https://a.com/x.js" || ct != "" {
		t.Fatalf("AssetHttp 提取失败: %q %q", u, ct)
	}
	u, _ = extractJSURL("https://a.com/raw.js")
	if u != "https://a.com/raw.js" {
		t.Fatalf("string 提取失败: %q", u)
	}
	u, _ = extractJSURL(12345)
	if u != "" {
		t.Fatalf("未知类型应返回空，得到 %q", u)
	}
}

func TestLooksLikeHTML(t *testing.T) {
	if !looksLikeHTML([]byte("<!DOCTYPE html><html></html>")) {
		t.Error("doctype 应判为 HTML")
	}
	if !looksLikeHTML([]byte("  <html lang=en>")) {
		t.Error("html 标签应判为 HTML")
	}
	if looksLikeHTML([]byte("function a(){return 1}")) {
		t.Error("JS 不应判为 HTML")
	}
}

// TestJSAuditFetchesAndScans 端到端：本地起 HTTP 服务提供含假凭据的 JS，
// 模块应下载落盘并命中 nuclei keys 规则。需要 NUCLEI_BIN 与 JS_AUDIT_KEYS 环境变量。
func TestJSAuditFetchesAndScans(t *testing.T) {
	bin := os.Getenv("NUCLEI_BIN")
	keysDir := os.Getenv("JS_AUDIT_KEYS")
	if bin == "" || keysDir == "" {
		t.Skip("未设置 NUCLEI_BIN / JS_AUDIT_KEYS，跳过端到端")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("nuclei 二进制不存在: %v", err)
	}
	if _, err := exec.LookPath(bin); err != nil {
		// 允许相对路径
		_ = err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`var cfg={aws:"AKIA` + "IOSFODNN7EXAMPLE" + `"};`))
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("body{}"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	collector := newCollectSink()
	m := NewJSAuditModule(context.Background(), collector, 2, keysDir)
	m.SetNucleiBinary(bin)
	m.SetScope(scope.New(nil))
	m.SetInput(make(chan interface{}, 10))

	done := make(chan error, 1)
	go func() { done <- m.ModuleRun() }()

	m.GetInput() <- UrlResult{Output: srv.URL + "/app.js", ContentType: "application/javascript"}
	m.GetInput() <- UrlResult{Output: srv.URL + "/style.css", ContentType: "text/css"}
	m.CloseInput()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ModuleRun 出错: %v", err)
		}
	case <-time.After(180 * time.Second):
		t.Fatal("ModuleRun 超时")
	}

	found := 0
	for _, r := range collector.results {
		if vr, ok := r.(VulnResult); ok {
			if vr.Type != "js_secret" {
				t.Errorf("Type 应为 js_secret，得到 %q", vr.Type)
			}
			if vr.Target != srv.URL+"/app.js" {
				t.Errorf("Target 应回填源 JS URL，得到 %q", vr.Target)
			}
			if !strings.HasPrefix(vr.MatchedAt, "http") {
				t.Errorf("MatchedAt 未回填源 URL: %q", vr.MatchedAt)
			}
			found++
		}
	}
	if found == 0 {
		t.Fatal("未命中任何密钥规则，端到端链路未打通")
	}
	t.Logf("命中 %d 条 js_secret", found)
}

// collectSink 是最小化的下游模块，只把收到的数据存下来。
type collectSink struct {
	mu      chan struct{}
	input   chan interface{}
	results []interface{}
}

func newCollectSink() *collectSink {
	s := &collectSink{mu: make(chan struct{}, 1), input: make(chan interface{}, 100)}
	s.mu <- struct{}{}
	return s
}

func (s *collectSink) ModuleRun() error {
	for v := range s.input {
		<-s.mu
		s.results = append(s.results, v)
		s.mu <- struct{}{}
	}
	return nil
}
func (s *collectSink) SetInput(ch chan interface{}) { s.input = ch }
func (s *collectSink) GetInput() chan interface{}   { return s.input }
func (s *collectSink) CloseInput()                  { close(s.input) }
func (s *collectSink) GetName() string              { return "CollectSink" }
