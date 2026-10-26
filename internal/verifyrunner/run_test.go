package verifyrunner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseRedLines 红线静态检查：超限/非法方法/变量闭包。
func TestParseRedLines(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"缺 id", "steps:\n  - name: a\n    request: {method: GET, url: \"https://{{host}}/\"}\n    expect: {status: 200}\n", "缺 id"},
		{"步骤超硬顶", oversizedSteps(), "超硬顶"},
		{"repeat 超限", "id: t1\nsteps:\n  - name: a\n    request: {method: GET, url: \"https://{{host}}/\", repeat: 9}\n    expect: {status: 200}\n", "repeat"},
		{"方法白名单", "id: t2\nsteps:\n  - name: a\n    request: {method: TRACE, url: \"https://{{host}}/\"}\n    expect: {status: 200}\n", "白名单"},
		{"并发声明拒绝", "id: t3\nsteps:\n  - name: a\n    request: {method: GET, url: \"https://{{host}}/\"}\n    expect: {status: 200}\nlimits: {concurrency: 4}\n", "串行"},
		{"总量超自报", "id: t4\nsteps:\n  - name: a\n    request: {method: GET, url: \"https://{{host}}/\", repeat: 4}\n    expect: {status: 200}\n  - name: b\n    request: {method: GET, url: \"https://{{host}}/b\", repeat: 4}\n    expect: {status: 200}\n  - name: c\n    request: {method: GET, url: \"https://{{host}}/c\", repeat: 4}\n    expect: {status: 200}\nlimits: {max_requests: 10}\n", "请求总量"},
		{"未定义变量", "id: t5\nsteps:\n  - name: a\n    request: {method: GET, url: \"https://{{host}}/{{undef}}\"}\n    expect: {status: 200}\n", "未定义变量"},
		{"正则非法", "id: t6\nsteps:\n  - name: a\n    request: {method: GET, url: \"https://{{host}}/\"}\n    expect: {regex: \"([bad\"}\n", "正则非法"},
		{"纯请求步骤", "id: t7\nsteps:\n  - name: a\n    request: {method: GET, url: \"https://{{host}}/\"}\n", "无意义"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadPlaybookFromBytes([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("期望拒绝，实际通过")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误信息 %q 不含 %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func oversizedSteps() string {
	var b strings.Builder
	b.WriteString("id: t0\nsteps:\n")
	for i := 0; i < MaxStepsHard+1; i++ {
		fmt.Fprintf(&b, "  - name: s%d\n    request: {method: GET, url: \"https://{{host}}/%d\"}\n    expect: {status: 200}\n", i, i)
	}
	return b.String()
}

// TestRunHappyPathWithExtraction 多步 + Cookie 状态 + 变量提取 + confirmed。
func TestRunHappyPathWithExtraction(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 步骤 1：登录种 cookie；步骤 2：带 cookie 读回（无 cookie 则 401）
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "xyz"})
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true,"token":"T-12345"}`))
	})
	mux.HandleFunc("/logfile", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err != nil || c.Value != "xyz" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`unauthorized`))
			return
		}
		_, _ = w.Write([]byte("SELECT password FROM users; SELECT token FROM sessions;"))
	})

	pbYAML := fmt.Sprintf(`
id: chain_test
refuted_status_in: [401, 403, 404]
steps:
  - name: login
    request: {method: POST, url: "%s/login", body: '{"u":"a"}'}
    expect: {status: 200, contains_any: ["ok", "good"]}
    extract: [{name: tok, regex: '"token":"([A-Z0-9-]+)"'}]
  - name: read_logfile
    request: {method: GET, url: "%s/logfile"}
    expect: {regex: "SELECT .+ FROM"}
`, srv.URL, srv.URL)
	pb, err := LoadPlaybookFromBytes([]byte(pbYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pb.VarsRequired) != 0 {
		t.Fatalf("无外部变量引用，VarsRequired = %v", pb.VarsRequired)
	}
	res, err := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "x"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("verdict = %s (%s)，steps=%+v", res.Verdict, res.Reason, res.Steps)
	}
	if res.Extracted["tok"] != "T-12345" {
		t.Fatalf("提取失败: %v", res.Extracted)
	}
	if res.Requests != 2 {
		t.Fatalf("请求数 = %d, want 2", res.Requests)
	}
}

// TestRunRefutedAndBlocked 失败语义：refuted_status_in 命中 → refuted；断言失败 → blocked。
func TestRunRefutedAndBlocked(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })

	pbRefuted, _ := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: ref
refuted_status_in: [401, 404]
steps:
  - name: probe
    request: {method: GET, url: "%s/404"}
    expect: {status: 200}
`, srv.URL)))
	res, err := Run(context.Background(), pbRefuted, RunOptions{Vars: map[string]string{"host": "x"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Verdict != VerdictRefuted {
		t.Fatalf("want refuted, got %s (%s)", res.Verdict, res.Reason)
	}

	pbBlocked, _ := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: blk
steps:
  - name: probe
    request: {method: GET, url: "%s/500"}
    expect: {status: 200}
`, srv.URL)))
	res2, _ := Run(context.Background(), pbBlocked, RunOptions{Vars: map[string]string{"host": "x"}})
	if res2.Verdict != VerdictBlocked {
		t.Fatalf("want blocked, got %s", res2.Verdict)
	}
	if res2.Steps[0].Status != 500 {
		t.Fatalf("失败步状态应保留到证据，实际 %d", res2.Steps[0].Status)
	}
}

// TestRunMissingVar 入参变量缺失 → error。
func TestRunMissingVar(t *testing.T) {
	pb, _ := LoadPlaybookFromBytes([]byte(`
id: needvar
steps:
  - name: a
    request: {method: GET, url: "https://{{host}}/{{seed_url}}"}
    expect: {status: 200}
`))
	if _, err := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "x"}}); err == nil {
		t.Fatal("缺 seed_url 应报错")
	}
}

// TestRedirectCrossHostStops 跨 host 302 停在 3xx 不跟随。
func TestRedirectCrossHostStops(t *testing.T) {
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	defer outer.Close()
	pb, _ := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: redir
steps:
  - name: r
    request: {method: GET, url: "%s/jump"}
    expect: {status: 302}
`, outer.URL)))
	res, _ := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "x"}})
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("跨 host 重定向应停在 302 并判 confirmed，got %s (%s)", res.Verdict, res.Reason)
	}
}

// TestMaxRequestsHardCap 运行期请求硬顶中止 → blocked。
func TestMaxRequestsHardCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	pb, _ := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: cap
steps:
  - name: a
    request: {method: GET, url: "%s/1"}
    expect: {status: 200}
  - name: b
    request: {method: GET, url: "%s/2"}
    expect: {status: 200}
`, srv.URL, srv.URL)))
	res, _ := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "x"}, MaxRequests: 1})
	if res.Verdict != VerdictBlocked || res.Requests != 1 {
		t.Fatalf("want blocked@1 request, got %s requests=%d", res.Verdict, res.Requests)
	}
}
