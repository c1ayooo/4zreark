package wih

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestProber 构造测试用探测器：限速与预算可调，单请求超时 2s。
func newTestProber(delay, budget time.Duration) *Prober {
	return NewProber(Config{
		PerSiteBudget:     budget,
		PerRequestTimeout: 2 * time.Second,
		RateDelay:         delay,
	})
}

// paths 把路径列表转成 literal 来源的候选。
func paths(ps ...string) []EndpointCandidate {
	out := make([]EndpointCandidate, 0, len(ps))
	for _, p := range ps {
		out = append(out, EndpointCandidate{Path: p, Source: "literal", Raw: p})
	}
	return out
}

// findEndpoint 按 URL 后缀查找探测结论。
func findEndpoint(res *SiteProbeResult, suffix string) *ProbeEndpoint {
	for i := range res.Endpoints {
		if strings.HasSuffix(res.Endpoints[i].URL, suffix) {
			return &res.Endpoints[i]
		}
	}
	return nil
}

// 用例 1：HEAD 200 直接采信；HEAD 405/501 回退 GET 并产出摘要；404 记 unverified
func TestWihProbeHeadGetFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/api/head405", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprint(w, "get-data")
	})
	mux.HandleFunc("/api/head501", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		fmt.Fprint(w, "fifty-one")
	})
	mux.HandleFunc("/api/missing", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := newTestProber(time.Millisecond, 10*time.Second).
		ProbeSite(context.Background(), srv.URL, paths("/api/ok", "/api/head405", "/api/head501", "/api/missing"))

	if res.Probed != 4 || len(res.Endpoints) != 4 {
		t.Fatalf("4 个候选都应拿到响应，got probed=%d endpoints=%d", res.Probed, len(res.Endpoints))
	}

	if ep := findEndpoint(res, "/api/ok"); ep == nil || ep.Method != "HEAD" || ep.StatusCode != 200 || !ep.Verified {
		t.Fatalf("/api/ok 应 HEAD 200 verified，got %+v", ep)
	} else if ep.Digest != "" {
		t.Fatalf("HEAD 不应产出摘要，got %s", ep.Digest)
	}

	if ep := findEndpoint(res, "/api/head405"); ep == nil || ep.Method != "GET" || ep.StatusCode != 200 || !ep.Verified {
		t.Fatalf("/api/head405 应回退 GET 200 verified，got %+v", ep)
	} else if len(ep.Digest) != 16 {
		t.Fatalf("GET 应产出 16 位摘要，got %q", ep.Digest)
	} else if ep.Allow != "GET" {
		t.Fatalf("405 响应应记录 Allow 头，got %+v", ep)
	}

	if ep := findEndpoint(res, "/api/head501"); ep == nil || ep.Method != "GET" || ep.StatusCode != 200 {
		t.Fatalf("/api/head501 应回退 GET 200，got %+v", ep)
	}

	if ep := findEndpoint(res, "/api/missing"); ep == nil || ep.StatusCode != 404 || ep.Verified {
		t.Fatalf("/api/missing 应 404 unverified，got %+v", ep)
	}
}

// 用例 2：重定向跳出同 host 标记 off_site 并停止；同 host 重定向正常跟随到最终 URL
func TestWihProbeRedirectOffSite(t *testing.T) {
	landing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "landing")
	}))
	defer landing.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/redir-off", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, landing.URL+"/landing", http.StatusFound)
	})
	mux.HandleFunc("/redir-local", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/ok", http.StatusFound)
	})
	mux.HandleFunc("/api/ok", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := newTestProber(time.Millisecond, 10*time.Second).
		ProbeSite(context.Background(), srv.URL, paths("/redir-off", "/redir-local"))

	// off_site 端点的 URL 已改写为重定向目标，按 OffSite 标记查找；
	// 同 host 重定向跟随到最终地址，按最终路径后缀查找。
	var off, local *ProbeEndpoint
	for i := range res.Endpoints {
		ep := &res.Endpoints[i]
		if ep.OffSite {
			off = ep
		}
		if strings.HasSuffix(ep.URL, "/api/ok") {
			local = ep
		}
	}
	if res.Probed != 2 {
		t.Fatalf("两个候选都应拿到响应，got %d", res.Probed)
	}
	if off == nil {
		t.Fatalf("跨 host 重定向应标记 off_site，got %+v", res.Endpoints)
	}
	if !strings.HasPrefix(off.URL, landing.URL) {
		t.Fatalf("off_site 应记录重定向目标 URL，got %s", off.URL)
	}
	if off.StatusCode != 302 {
		t.Fatalf("off_site 记录的是同源侧 3xx，got %d", off.StatusCode)
	}

	if local == nil || local.OffSite {
		t.Fatalf("同 host 重定向不应标记 off_site，got %+v", local)
	}
	if !strings.HasSuffix(local.URL, "/api/ok") || local.StatusCode != 200 || !local.Verified {
		t.Fatalf("同 host 重定向应跟随到 /api/ok 200，got %+v", local)
	}
}

// 用例 3：软 404 基线——任意路径都返回相同成功形态的站点，其 2xx 记 unverified
func TestWihProbeSoft404(t *testing.T) {
	softBody := strings.Repeat("x", 64) + " not found"
	// 显式回 Content-Length：HEAD 没有长度证据时不参与软 404 判定（实现里的既定限制）
	mux := http.NewServeMux()
	// 根路径兜底：随机基线路径与 /api/soft 都返回同一成功形态
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprint(len(softBody)))
		fmt.Fprint(w, softBody)
	})
	mux.HandleFunc("/api/real", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"real":1}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := newTestProber(time.Millisecond, 10*time.Second).
		ProbeSite(context.Background(), srv.URL, paths("/api/soft", "/api/real"))

	soft := findEndpoint(res, "/api/soft")
	if soft == nil || soft.StatusCode != 200 || soft.Verified {
		t.Fatalf("命中软 404 基线的 200 应为 unverified，got %+v", soft)
	}
	real := findEndpoint(res, "/api/real")
	if real == nil || !real.Verified {
		t.Fatalf("形态不同的 /api/real 应 verified，got %+v", real)
	}
}

// 用例 4：站点预算生效——预算耗尽后停止探测，不会打完所有候选
func TestWihProbeBudget(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/slow/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "slow")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cands := make([]EndpointCandidate, 0, 12)
	for i := 0; i < 12; i++ {
		cands = append(cands, EndpointCandidate{Path: fmt.Sprintf("/slow/%d", i), Source: "literal"})
	}

	res := newTestProber(time.Millisecond, 60*time.Millisecond).
		ProbeSite(context.Background(), srv.URL, cands)

	if res.Probed == 0 || res.Probed >= len(cands) {
		t.Fatalf("预算 60ms 下应探到部分候选（0 < probed < 12），got %d", res.Probed)
	}
}

// 用例 5：限速生效——请求间隔不小于 RateDelay
func TestWihProbeRateDelay(t *testing.T) {
	mux := http.NewServeMux()
	for _, p := range []string{"/r/1", "/r/2", "/r/3"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "ok")
		})
	}
	// 根路径返回 200，让基线探测也走限速路径
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "root")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	start := time.Now()
	res := newTestProber(40*time.Millisecond, 10*time.Second).
		ProbeSite(context.Background(), srv.URL, paths("/r/1", "/r/2", "/r/3"))
	elapsed := time.Since(start)

	// 3 个候选 + 2 个基线请求 = 5 次限速间隔，宽松下界 150ms
	if res.Probed != 3 {
		t.Fatalf("3 个候选都应探到，got %d", res.Probed)
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("RateDelay=40ms 下 5 次请求应至少 150ms，实际 %v", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("限速不应把探测拖到 5s 以上，实际 %v", elapsed)
	}
}

// 用例 6：请求不带 Cookie，Set-Cookie / 任何凭证字段不落入结果
func TestWihProbeNoCredentialLeak(t *testing.T) {
	var sawCookie int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/greet", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			atomic.StoreInt32(&sawCookie, 1)
		}
		w.Header().Set("Set-Cookie", "session=secret123; Path=/")
		fmt.Fprint(w, `{"c":1}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := newTestProber(time.Millisecond, 10*time.Second).
		ProbeSite(context.Background(), srv.URL, paths("/api/greet"))

	ep := findEndpoint(res, "/api/greet")
	if ep == nil || !ep.Verified {
		t.Fatalf("/api/cookie 应 200 verified，got %+v", ep)
	}

	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lower := strings.ToLower(string(b))
	for _, banned := range []string{"set-cookie", "session", "cookie", "authorization"} {
		if strings.Contains(lower, banned) {
			t.Fatalf("结果不应包含 %q，got %s", banned, b)
		}
	}
	if atomic.LoadInt32(&sawCookie) != 0 {
		t.Fatal("探测请求不应携带 Cookie 头")
	}
}

// 用例 7：ctx 取消立即停止探测
func TestWihProbeContextCancel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	res := newTestProber(50*time.Millisecond, time.Minute).
		ProbeSite(ctx, srv.URL, paths("/api/1", "/api/2", "/api/3"))

	if res.Probed >= 3 {
		t.Fatalf("ctx 取消后不应探完所有候选，got %d", res.Probed)
	}
}
