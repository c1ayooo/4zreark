package vhostdedup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// srvPort 取 httptest 服务监听的端口。
func srvPort(srv *httptest.Server) int {
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

// closedPort 找一个当前无人监听的端口（起一个监听再立刻关掉）。
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestLengthBucket 长度按十进制位数（数量级）分桶，<=0 单独成桶。
func TestLengthBucket(t *testing.T) {
	cases := []struct {
		n    int
		want int
	}{
		{-5, 0}, {0, 0},
		{1, 1}, {9, 1},
		{10, 2}, {99, 2},
		{100, 3}, {999, 3},
		{1000, 4}, {512000, 6},
	}
	for _, c := range cases {
		if got := LengthBucket(c.n); got != c.want {
			t.Fatalf("LengthBucket(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}

// TestLooksLikeBaseline 基线相似判定：标题一致 + 长度同桶 + 无业务特征才剔除，
// 且标题或 favicon 至少一样非空（双方全空证据不足，放行）。
func TestLooksLikeBaseline(t *testing.T) {
	parked := Response{StatusCode: 200, BodyLen: 4321, Title: "Parked Page"}
	cases := []struct {
		name     string
		baseline Response
		cand     Response
		want     bool
	}{
		{"同页（大小写与空白差异）", parked,
			Response{StatusCode: 200, BodyLen: 4400, Title: "  PARKED\npage "}, true},
		{"标题一致且 favicon 一致非空", Response{StatusCode: 200, BodyLen: 4321, Title: "Parked Page", FaviconMMH3: "1097970861"},
			Response{StatusCode: 200, BodyLen: 4300, Title: "Parked Page", FaviconMMH3: "1097970861"}, true},
		{"双方无标题但同 favicon 非空", Response{BodyLen: 500, FaviconMMH3: "42"},
			Response{BodyLen: 560, FaviconMMH3: "42"}, true},
		{"独立标题 = 业务站点", parked,
			Response{StatusCode: 200, BodyLen: 4300, Title: "Real Business Portal"}, false},
		{"长度跨桶", parked,
			Response{StatusCode: 200, BodyLen: 98765, Title: "Parked Page"}, false},
		{"候选带自有 favicon（与空基线不同）", parked,
			Response{StatusCode: 200, BodyLen: 4300, Title: "Parked Page", FaviconMMH3: "1097970861"}, false},
		{"双方全空证据不足", Response{BodyLen: 500},
			Response{BodyLen: 560}, false},
		{"状态码不同但标题长度同形仍剔除（基线测量口径不含状态码）", parked,
			Response{StatusCode: 403, BodyLen: 4350, Title: "Parked Page"}, true},
	}
	for _, c := range cases {
		if got := LooksLikeBaseline(c.baseline, c.cand); got != c.want {
			t.Fatalf("%s: LooksLikeBaseline = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestFormKey 形态键由状态码 + 长度桶 + 归一化标题构成。
func TestFormKey(t *testing.T) {
	a := Response{StatusCode: 200, BodyLen: 4321, Title: "Parked Page"}
	b := Response{StatusCode: 200, BodyLen: 4999, Title: "parked  page"}
	if FormKey(a) != FormKey(b) {
		t.Fatalf("同形态观测应得到同键: %q vs %q", FormKey(a), FormKey(b))
	}
	c := Response{StatusCode: 200, BodyLen: 4321, Title: "Other"}
	if FormKey(a) == FormKey(c) {
		t.Fatal("不同标题不应同键")
	}
}

// TestMarkClusters 聚类兜底：同形态达到 ClusterMinGroup 整组打标，不足不打。
func TestMarkClusters(t *testing.T) {
	mk := func(title string, l int) Candidate {
		return Candidate{Response: Response{StatusCode: 200, BodyLen: l, Title: title}}
	}

	// 刚好阈值：整组打标。
	same := make([]Candidate, ClusterMinGroup)
	for i := range same {
		same[i] = mk("Parked", 500)
	}
	marked := MarkClusters(same)
	for i, m := range marked {
		if !m {
			t.Fatalf("%d 个同形态应整组打标，第 %d 个未打", ClusterMinGroup, i)
		}
	}

	// 差一个：谁也不打。
	short := append(append([]Candidate{}, same[:ClusterMinGroup-1]...), mk("Other", 500))
	for i, m := range MarkClusters(short) {
		if m {
			t.Fatalf("不足阈值不应打标，第 %d 个被打", i)
		}
	}

	// 混合两组：够数的组整组打，不够的组不动。
	mixed := append(append([]Candidate{}, same...), same[:ClusterMinGroup-1]...)
	for i := range mixed {
		mixed[i] = mk("Parked", 500)
	}
	for i := ClusterMinGroup; i < len(mixed); i++ {
		mixed[i] = mk("Wheel", 900)
	}
	marked = MarkClusters(mixed)
	for i, m := range marked {
		want := i < ClusterMinGroup
		if m != want {
			t.Fatalf("混合组第 %d 个打标 = %v, want %v", i, m, want)
		}
	}
}

// TestBaselineProbeForm 基线探针形态：每 IP 恰好 MaxBaselineProbes 个请求，
// Host 是互不相同的随机名（.invalid 保留 TLD），UA 与指纹探测一致。
func TestBaselineProbeForm(t *testing.T) {
	var mu sync.Mutex
	var hosts, uas []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		uas = append(uas, r.UserAgent())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><title>Welcome to nginx!</title><body>%s</body></html>", strings.Repeat("x", 300))
	}))
	defer srv.Close()

	base, ok := New(&http.Client{Timeout: 5 * time.Second}).
		Baseline(context.Background(), "http", "127.0.0.1", srvPort(srv))
	if !ok {
		t.Fatal("稳定默认页应建立基线成功")
	}
	if base.StatusCode != 200 || base.Title != "Welcome to nginx!" || base.BodyLen == 0 {
		t.Fatalf("基线观测不符: %+v", base)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hosts) != MaxBaselineProbes {
		t.Fatalf("应恰好发 %d 个探针，实际 %d", MaxBaselineProbes, len(hosts))
	}
	for i, h := range hosts {
		if !strings.HasSuffix(h, ".invalid") {
			t.Fatalf("探针 Host %q 应回退到 .invalid 保留域", h)
		}
		if i > 0 && h == hosts[0] {
			t.Fatalf("两次探针的随机 Host 不应相同: %q", h)
		}
	}
	// 基线必须长得像指纹探测（浏览器 UA），否则源站按 UA 差异化响应时观测不可比。
	if !strings.Contains(uas[0], "Chrome/") || !strings.HasPrefix(uas[0], "Mozilla/5.0") {
		t.Fatalf("基线探针 UA 应与指纹探测同款浏览器 UA，got %q", uas[0])
	}
}

// TestBaselineNon200Recorded 非 200 的默认页（403 兜底）也是合法基线：照常记录，
// 与它同形的候选照常剔除。
func TestBaselineNon200Recorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "<html><title>Forbidden</title><body>%s</body></html>", strings.Repeat("x", 120))
	}))
	defer srv.Close()

	base, ok := New(&http.Client{Timeout: 5 * time.Second}).
		Baseline(context.Background(), "http", "127.0.0.1", srvPort(srv))
	if !ok {
		t.Fatal("403 兜底页应建立基线成功")
	}
	if base.StatusCode != http.StatusForbidden || base.Title != "Forbidden" {
		t.Fatalf("403 基线应原样记录状态码与标题: %+v", base)
	}
	same := Response{StatusCode: 403, BodyLen: base.BodyLen, Title: "Forbidden"}
	if !LooksLikeBaseline(base, same) {
		t.Fatal("与 403 基线同形的候选应剔除")
	}
	biz := Response{StatusCode: 403, BodyLen: base.BodyLen, Title: "WAF Block"}
	if LooksLikeBaseline(base, biz) {
		t.Fatal("独立标题的候选不应剔除")
	}
}

// TestBaselineTimeoutFails 探针超时 = 放弃去噪。
func TestBaselineTimeoutFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, "<html><title>slow</title></html>")
	}))
	defer srv.Close()

	p := New(&http.Client{}) // 客户端无全局超时，靠 Prober.Timeout 兜底
	p.Timeout = 50 * time.Millisecond
	if _, ok := p.Baseline(context.Background(), "http", "127.0.0.1", srvPort(srv)); ok {
		t.Fatal("探针超时应视为失败并放弃去噪")
	}
}

// TestBaselineInconsistentShapeFails 源站对随机 Host 轮换响应（反侦察/动态内容），
// 两次观测不同形 → 基线无法定义 → 放弃。
func TestBaselineInconsistentShapeFails(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		title := "Wheel A"
		if atomic.AddInt32(&n, 1)%2 == 0 {
			title = "Wheel B"
		}
		fmt.Fprintf(w, "<html><title>%s</title><body>%s</body></html>", title, strings.Repeat("x", 200))
	}))
	defer srv.Close()

	if _, ok := New(&http.Client{Timeout: 5 * time.Second}).
		Baseline(context.Background(), "http", "127.0.0.1", srvPort(srv)); ok {
		t.Fatal("两次观测不同形应放弃基线")
	}
}

// TestBaselineTransportErrorFails 连不上（端口关闭）= 放弃去噪。
func TestBaselineTransportErrorFails(t *testing.T) {
	port := closedPort(t)
	if _, ok := New(&http.Client{Timeout: 2 * time.Second}).
		Baseline(context.Background(), "http", "127.0.0.1", port); ok {
		t.Fatal("连接失败应视为探针失败")
	}
}

// TestBaselineRejectsBadArgs 参数不合法（nil 客户端/空 IP/非法端口/协议）直接失败，
// 不发任何请求。
func TestBaselineRejectsBadArgs(t *testing.T) {
	p := New(nil)
	if _, ok := p.Baseline(context.Background(), "http", "127.0.0.1", 80); ok {
		t.Fatal("nil 客户端应失败")
	}
	p = New(&http.Client{Timeout: time.Second})
	if _, ok := p.Baseline(context.Background(), "http", "", 80); ok {
		t.Fatal("空 IP 应失败")
	}
	if _, ok := p.Baseline(context.Background(), "http", "127.0.0.1", 0); ok {
		t.Fatal("端口 0 应失败")
	}
	if _, ok := p.Baseline(context.Background(), "ftp", "127.0.0.1", 80); ok {
		t.Fatal("非 http/https 协议应失败")
	}
}
