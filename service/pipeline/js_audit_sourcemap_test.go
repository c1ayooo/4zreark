package pipeline

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/sourcemap"
)

// httptest 监听 127.0.0.1，safehttp 扫描档默认拒环回；测试进程统一放行
//（与 service/probe_test.go 同款）。
func init() { os.Setenv("ZRE_SAFEHTTP_ALLOW_PRIVATE", "1") }

// newTestJSAuditModule 构造不走 nuclei 的审计模块（scanner 为 nil 不影响
// restoreSourceMap——它只依赖 client/scope/files）。
func newTestJSAuditModule(t *testing.T) (*JSAuditModule, string) {
	t.Helper()
	m := NewJSAuditModule(t.Context(), nil, 1, "")
	workDir := t.TempDir()
	return m, workDir
}

// 路径 1：JS 尾部 sourceMappingURL data URI（webpack 内联形态），
// sourcesContent 完整 → 源码还原落盘并登记命中线索。
func TestRestoreSourceMapInlineDataURI(t *testing.T) {
	m, workDir := newTestJSAuditModule(t)

	srcContent := "const API_KEY = 'sk-live-test-12345';\n"
	sm := fmt.Sprintf(`{"version":3,"sources":["webpack://app/./src/config.ts"],"sourcesContent":[%s],"mappings":"AAAA"}`,
		mustJSONString(srcContent))
	inline := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(sm))

	jsURL := "https://target.example.com/static/app.js"
	local := filepath.Join(workDir, "aaaa.js")
	jsBody := "var x=1;\n//# sourceMappingURL=" + inline + "\n"
	if err := os.WriteFile(local, []byte(jsBody), 0o600); err != nil {
		t.Fatal(err)
	}

	n := m.restoreSourceMap(workDir, jsURL, local)
	if n != 1 {
		t.Fatalf("还原数 = %d, want 1", n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.restoredTotal != 1 {
		t.Fatalf("restoredTotal = %d", m.restoredTotal)
	}
	// 找到落盘文件且内容是原始源码
	found := false
	for name, clue := range m.files {
		if strings.Contains(name, "-map-") {
			found = true
			data, err := os.ReadFile(filepath.Join(workDir, name))
			if err != nil || !strings.Contains(string(data), "sk-live-test-12345") {
				t.Fatalf("还原文件内容不对: %v %q", err, data)
			}
			if !strings.Contains(clue, "[source: src/config.ts]") {
				t.Fatalf("命中线索缺源路径: %q", clue)
			}
		}
	}
	if !found {
		t.Fatal("还原文件未登记进 files")
	}
}

// 路径 2：注释指向远程 .map（httptest 承载），scope 放行 → 还原。
func TestRestoreSourceMapRemoteRef(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/main.js":
			fmt.Fprint(w, "var y=2;\n//# sourceMappingURL=/static/main.js.map\n")
		case "/static/main.js.map":
			fmt.Fprintf(w, `{"version":3,"sources":["./src/login.js"],"sourcesContent":["const pwd='admin123';"],"mappings":"AAAA"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	m, workDir := newTestJSAuditModule(t)
	jsURL := ts.URL + "/static/main.js"
	local := filepath.Join(workDir, "bbbb.js")
	body, err := fetchForTest(t, ts, jsURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if n := m.restoreSourceMap(workDir, jsURL, local); n != 1 {
		t.Fatalf("还原数 = %d, want 1", n)
	}
}

// 路径 3：无 sourceMappingURL 注释 → 同路径 .map 探测命中。
func TestRestoreSourceMapAdjacentProbe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/app.js.map" {
			fmt.Fprintf(w, `{"version":3,"sources":["src/token.js"],"sourcesContent":["token='ghp_abcdef';"],"mappings":"AAAA"}`)
			return
		}
		fmt.Fprint(w, "var z=3;\n")
	}))
	defer ts.Close()

	m, workDir := newTestJSAuditModule(t)
	jsURL := ts.URL + "/static/app.js"
	local := filepath.Join(workDir, "cccc.js")
	body, _ := fetchForTest(t, ts, jsURL)
	if err := os.WriteFile(local, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if n := m.restoreSourceMap(workDir, jsURL, local); n != 1 {
		t.Fatalf("还原数 = %d, want 1（应走 .map 探测）", n)
	}
}

// 路径 4：无 map 可得 → 静默 0，不落任何文件。
func TestRestoreSourceMapNoMap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "var plain=1;\n")
	}))
	defer ts.Close()

	m, workDir := newTestJSAuditModule(t)
	jsURL := ts.URL + "/plain.js"
	local := filepath.Join(workDir, "dddd.js")
	body, _ := fetchForTest(t, ts, jsURL)
	if err := os.WriteFile(local, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := m.restoreSourceMap(workDir, jsURL, local); n != 0 {
		t.Fatalf("还原数 = %d, want 0", n)
	}
}

// 路径 5：map 无 sourcesContent → 0 还原，但路径清单有日志（不打断审计）。
func TestRestoreSourceMapNoContent(t *testing.T) {
	sm := `{"version":3,"sources":["src/a.js","src/b.js"],"mappings":"AAAA;AACAA"}`
	inline := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(sm))

	m, workDir := newTestJSAuditModule(t)
	jsURL := "https://target.example.com/x.js"
	local := filepath.Join(workDir, "eeee.js")
	if err := os.WriteFile(local, []byte("//# sourceMappingURL="+inline+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := m.restoreSourceMap(workDir, jsURL, local); n != 0 {
		t.Fatalf("还原数 = %d, want 0", n)
	}
	// sources 路径清单本身可读（目录结构泄露价值）
	parsed, err := sourcemap.Parse([]byte(sm))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.SourcePaths()) != 2 {
		t.Fatalf("SourcePaths = %v", parsed.SourcePaths())
	}
}

// fetchForTest 用模块同款 HTTP 客户端拉一份 JS 落盘内容（测试辅助）。
func fetchForTest(t *testing.T, ts *httptest.Server, url string) ([]byte, error) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}

func mustJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// 防回归：restoreSourceMap 内部持 m.mu，调用方绝不能在持锁状态下调用
//（Mutex 不可重入 → fetch goroutine 死锁 → 任务永久卡 running，端到端实测踩过）。
// 本测试模拟生产调用路径：先登记 files（短暂持锁），再无锁调用还原，并发跑。
func TestRestoreSourceMapNoReentrantLock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".map") {
			fmt.Fprintf(w, `{"version":3,"sources":["src/a.ts"],"sourcesContent":["const k='AKIAIOSFODNN7EXAMPLE';"],"mappings":"AAAA"}`)
			return
		}
		fmt.Fprint(w, "//# sourceMappingURL=app.js.map\n")
	}))
	defer ts.Close()

	m, workDir := newTestJSAuditModule(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			jsURL := fmt.Sprintf("%s/app%d.js", ts.URL, i)
			local := filepath.Join(workDir, fmt.Sprintf("f%d.js", i))
			body, _ := fetchForTest(t, ts, jsURL)
			if err := os.WriteFile(local, body, 0o600); err != nil {
				t.Error(err)
				return
			}
			m.mu.Lock()
			m.files[fmt.Sprintf("f%d.js", i)] = jsURL
			m.mu.Unlock()
			m.restoreSourceMap(workDir, jsURL, local)
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("restoreSourceMap 在持锁调用路径下死锁（或超慢）")
	}
	if m.restoredTotal != 3 {
		t.Fatalf("restoredTotal = %d, want 3", m.restoredTotal)
	}
}
