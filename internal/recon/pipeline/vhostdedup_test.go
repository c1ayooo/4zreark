package pipeline

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/internal/recon/vhostdedup"
)

// mkSite 构造一个探活成功的候选：obs 与 resp 的口径与 stage 4 集成代码一致
// （resp.BodyLen = 响应体长度）。
func mkSite(url, ip string, port, status int, title, body, favicon string) aliveSite {
	return aliveSite{
		target: httpTarget{host: "h.example.com", ip: ip, port: port, scheme: "http"},
		url:    url,
		obs:    fingerprint.Observation{Status: status, Title: title, IconHash: favicon},
		resp: vhostdedup.Response{
			StatusCode: status, BodyLen: len(body), Title: title, FaviconMMH3: favicon,
		},
	}
}

// parkedBody / realBody 模拟两类源站页面：任意 Host 都返回的停放默认页，
// 与只在真实 vhost 上存在的业务页。
var (
	parkedBody = fmt.Sprintf("<html><title>Parked Page</title><body>%s</body></html>", strings.Repeat("p ", 200))
	realBody   = fmt.Sprintf("<html><title>Real Business Portal</title><body>%s</body></html>", strings.Repeat("biz ", 400))
)

// catchAllServer 起一个 catch-all 假源站：random Host / 任意域名都拿到停放页，
// 只有 Host 以 real. 开头时返回业务页。
func catchAllServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "real.") {
			fmt.Fprint(w, realBody)
			return
		}
		fmt.Fprint(w, parkedBody)
	}))
}

// TestVhostFilterBaselineRemovesCatchAll 基线同形且无业务特征的候选剔除，独立
// 标题的业务站点放行。
func TestVhostFilterBaselineRemovesCatchAll(t *testing.T) {
	srv := catchAllServer(t)
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	alive := []aliveSite{
		mkSite(fmt.Sprintf("http://a.example.com:%d", port), "127.0.0.1", port, 200, "Parked Page", parkedBody, ""),
		mkSite(fmt.Sprintf("http://b.example.com:%d", port), "127.0.0.1", port, 200, "Parked Page", parkedBody, ""),
		mkSite(fmt.Sprintf("http://real.example.com:%d", port), "127.0.0.1", port, 200, "Real Business Portal", realBody, ""),
	}

	drop, mark, vs := vhostFilter(context.Background(), &http.Client{Timeout: 5 * time.Second}, alive)

	if !drop[0] || !drop[1] {
		t.Fatalf("两个与基线同形的停放候选应剔除, drop=%v", drop)
	}
	if drop[2] {
		t.Fatal("独立标题的业务站点不应剔除")
	}
	if len(mark) != 0 {
		t.Fatalf("3 个候选不构成聚类，不应有打标: %v", mark)
	}
	if vs.Filtered != 2 || vs.BaselineFailed != 0 || vs.ClusterMarked != 0 {
		t.Fatalf("统计不符: %+v", vs)
	}
}

// TestVhostFilterClusterMarksSurvivors 基线不成立（源站对随机 Host 轮换响应）
// 时全部候选放行，同形态 ≥ 阈值的组走聚类兜底整组打标（只打标不剔除）。
func TestVhostFilterClusterMarksSurvivors(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		title := "Wheel A"
		if atomic.AddInt32(&n, 1)%2 == 0 {
			title = "Wheel B"
		}
		fmt.Fprintf(w, "<html><title>%s</title><body>%s</body></html>", title, strings.Repeat("x", 250))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	alive := make([]aliveSite, 0, vhostdedup.ClusterMinGroup)
	for i := 0; i < vhostdedup.ClusterMinGroup; i++ {
		body := fmt.Sprintf("<html><title>Parked Page</title><body>%s</body></html>", strings.Repeat("p ", 200))
		alive = append(alive, mkSite(fmt.Sprintf("http://s%d.example.com:%d", i, port), "127.0.0.1", port, 200, "Parked Page", body, ""))
	}

	drop, mark, vs := vhostFilter(context.Background(), &http.Client{Timeout: 5 * time.Second}, alive)

	if len(drop) != 0 {
		t.Fatalf("基线失败时应全部放行, drop=%v", drop)
	}
	if vs.BaselineFailed != 1 {
		t.Fatalf("该 IP 基线应记一次失败: %+v", vs)
	}
	if len(mark) != vhostdedup.ClusterMinGroup || vs.ClusterMarked != vhostdedup.ClusterMinGroup {
		t.Fatalf("%d 个同形态幸存者应整组打标: mark=%v stats=%+v", vhostdedup.ClusterMinGroup, mark, vs)
	}
	for i := 0; i < vhostdedup.ClusterMinGroup; i++ {
		if !mark[i] {
			t.Fatalf("第 %d 个候选应被打标", i)
		}
	}
}

// TestVhostFilterProbeFailureReleasesAll 探针完全失败（端口不通）= 放弃去噪，
// 候选全部放行并计入失败。
func TestVhostFilterProbeFailureReleasesAll(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // 留下一个无人监听的端口

	alive := []aliveSite{
		mkSite(fmt.Sprintf("http://a.example.com:%d", port), "127.0.0.1", port, 200, "Parked Page", parkedBody, ""),
		mkSite(fmt.Sprintf("http://b.example.com:%d", port), "127.0.0.1", port, 200, "Parked Page", parkedBody, ""),
	}
	drop, mark, vs := vhostFilter(context.Background(), &http.Client{Timeout: 5 * time.Second}, alive)

	if len(drop) != 0 || len(mark) != 0 {
		t.Fatalf("探针失败应全部放行: drop=%v mark=%v", drop, mark)
	}
	if vs.BaselineFailed != 1 || vs.Filtered != 0 || vs.ClusterMarked != 0 {
		t.Fatalf("统计不符: %+v", vs)
	}
}

// TestVhostFilterOneBaselinePerIP 成本红线：一个 IP 只建一次基线（首个候选的
// scheme/port），其余候选只做比较、不再发探针。
func TestVhostFilterOneBaselinePerIP(t *testing.T) {
	var hits1, hits2 int32
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits1, 1)
		fmt.Fprint(w, parkedBody)
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits2, 1)
		fmt.Fprint(w, parkedBody)
	}))
	defer srv2.Close()
	port1 := srv1.Listener.Addr().(*net.TCPAddr).Port
	port2 := srv2.Listener.Addr().(*net.TCPAddr).Port

	alive := []aliveSite{
		mkSite(fmt.Sprintf("http://a.example.com:%d", port1), "127.0.0.1", port1, 200, "Parked Page", parkedBody, ""),
		mkSite(fmt.Sprintf("http://b.example.com:%d", port2), "127.0.0.1", port2, 200, "Parked Page", parkedBody, ""),
	}
	drop, _, vs := vhostFilter(context.Background(), &http.Client{Timeout: 5 * time.Second}, alive)

	// 同 IP 只对首个候选的端口发基线探针，第二个端口 0 请求。
	if got := atomic.LoadInt32(&hits1); got != int32(vhostdedup.MaxBaselineProbes) {
		t.Fatalf("首个端口应恰好 %d 个基线请求，实际 %d", vhostdedup.MaxBaselineProbes, got)
	}
	if got := atomic.LoadInt32(&hits2); got != 0 {
		t.Fatalf("其余端口不应发探针，实际 %d 个", got)
	}
	if !drop[0] || !drop[1] || vs.Filtered != 2 {
		t.Fatalf("两个同形候选都应剔除: drop=%v stats=%+v", drop, vs)
	}
}

// TestVhostFilterSkipsUnknownIPAndDisabled 无 IP 的候选与 nil 客户端都直接放行，
// 已取消的 ctx 不探测也不计数。
func TestVhostFilterSkipsUnknownIPAndDisabled(t *testing.T) {
	alive := []aliveSite{
		mkSite("http://a.example.com", "", 80, 200, "Parked Page", parkedBody, ""),
	}
	drop, mark, vs := vhostFilter(context.Background(), &http.Client{Timeout: 5 * time.Second}, alive)
	if len(drop) != 0 || len(mark) != 0 || vs != (vhostStats{}) {
		t.Fatalf("无 IP 候选应原样放行且不计数: drop=%v mark=%v stats=%+v", drop, mark, vs)
	}

	drop, mark, vs = vhostFilter(context.Background(), nil, alive)
	if len(drop) != 0 || len(mark) != 0 || vs != (vhostStats{}) {
		t.Fatalf("nil 客户端应整体跳过去噪: drop=%v mark=%v stats=%+v", drop, mark, vs)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	drop, mark, vs = vhostFilter(ctx, &http.Client{Timeout: 5 * time.Second}, alive)
	if len(drop) != 0 || len(mark) != 0 || vs != (vhostStats{}) {
		t.Fatalf("已取消的 ctx 应直接放行且不计数: drop=%v mark=%v stats=%+v", drop, mark, vs)
	}
}
