package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// 1000 词字典 + 软 404 靶场：验证 spray 可用、限速生效、软 404 不误报。
func TestSpray1000WordlistSoft404(t *testing.T) {
	scanner := webscan.NewSprayScanner()
	if !scanner.IsAvailable() {
		t.Skip("跳过：tools/linux/spray 不存在")
	}

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<title>Admin</title><h1>admin panel</h1>"))
		case "/secret":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<title>Forbidden</title>denied"))
		default:
			// 任意路径都返回同样的 200 页面：典型软 404。
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<title>Not Found</title>" + strings.Repeat("soft-404-page ", 128)))
		}
	}))
	defer srv.Close()

	dict := filepath.Join(t.TempDir(), "dict.txt")
	var b strings.Builder
	b.WriteString("admin\nsecret\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "missing-%04d\n", i)
	}
	if err := os.WriteFile(dict, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner.Concurrency = 50
	scanner.RateLimit = 200
	scanner.Depth = 0
	scanner.EnableFingerprint = false
	scanner.EnableCrawl = false
	scanner.EnableBackup = false
	scanner.EnableCommon = false

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	start := time.Now()
	res, err := scanner.ScanWithWordlist(ctx, srv.URL, []string{dict})
	if err != nil {
		t.Fatalf("spray 执行失败: %v", err)
	}
	elapsed := time.Since(start)

	hasAdmin := false
	for _, e := range res.Results {
		if strings.HasSuffix(strings.TrimRight(e.URL, "/"), "/admin") || strings.Trim(e.Path, "/") == "admin" {
			hasAdmin = true
		}
	}
	if !hasAdmin {
		t.Fatalf("应命中 /admin，实际 %d 条: %+v", len(res.Results), res.Results)
	}

	if got := requests.Load(); got < 1000 {
		t.Errorf("1002 词至少应发 1000 次请求，实际 %d", got)
	}
	if elapsed > 30*time.Second {
		t.Errorf("1000 词在 200 req/s 下耗时过长: %s", elapsed)
	}

	// 软 404 过滤后不应留下 missing-* 路径。
	filtered := webscan.FilterSoft404Entries(ctx, res.Results, nil)
	for _, e := range filtered {
		if strings.Contains(e.URL, "missing-") || strings.Contains(e.Path, "missing-") {
			t.Fatalf("软 404 路径未被过滤: %s", e.URL)
		}
	}
	t.Logf("spray: 请求 %d 次，原始结果 %d 条，过滤后 %d 条，耗时 %s",
		requests.Load(), len(res.Results), len(filtered), elapsed)
}
