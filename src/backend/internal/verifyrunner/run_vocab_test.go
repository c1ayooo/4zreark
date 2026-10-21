package verifyrunner

// run_vocab_test.go —— V1/V2/V3 步骤原语运行语义（施工单
// 《verify_run步骤原语扩展与编排蒸馏》§三）：
//   - tcp：本机 listener 跑 banner 断言通过/失败两路（无外网依赖）、
//     连接失败→blocked、connect_ok=false + 明确拒绝（RST）→ confirmed；
//   - dns：注入桩 resolver（resolver 平台侧固定，仅测试注入），断言命中/不命中、
//     NXDOMAIN 也是可观测结论、查询计入 max_requests 硬顶；
//   - V3：resp_header_contains/regex 与 duration_ms_lt/gt 各自命中/不命中。

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startTCPProbeServer 起本机 TCP 服务：接受连接 → 读一次客户端 payload（若有）→
// 写 banner → 短暂保持后关闭（模拟 Redis/MySQL 类「命令-回显/连上即发」形态）。
// 网络隔离口径与既有 run_test.go 一致：只绑 127.0.0.1，端口随机。
func startTCPProbeServer(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 128)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf) // 步骤可能不带 payload（connect_ok-only 判据）
				_, _ = c.Write([]byte(banner))
				time.Sleep(150 * time.Millisecond) // 模拟服务常驻，客户端读 banner 走截断/超时路径
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// stubTCPDialer tcp 步拨号桩。「连接被明确拒绝（RST）」语义的用例必须用它注入，
// 不依赖真实回环行为：部分 WSL2 宿主上 Windows 侧 TUN 会间歇接管已关端口的
// 握手（连刚关闭的 127.0.0.1 端口竟握手成功），依赖真实 RST 的用例必假红
// （2026-09-29 实测：单跑必挂、整包可能绿）。
type stubTCPDialer struct {
	err error
}

func (s stubTCPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, s.err
}

// refusedDialErr 明确拒绝（等价收到 RST）：isConnRefused 的 errors.Is 能命中
// （*os.SyscallError 经 Unwrap 到 syscall.ECONNREFUSED）。
func refusedDialErr() error {
	return os.NewSyscallError("connect", syscall.ECONNREFUSED)
}

func tcpPlaybook(t *testing.T, port int, expect string) *Playbook {
	t.Helper()
	pb, err := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: tcp_vocab
steps:
  - name: redis_probe
    kind: tcp
    request: {host: "127.0.0.1", port: %d, payload_hex: "2a310d0a"}
    expect: %s
    extract: [{name: redis_ver, regex: "redis_version:([0-9.]+)", from: banner}]
limits: {per_step_timeout_ms: 1500}
`, port, expect)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return pb
}

// TestRunTCPBannerPass 未授权服务判据：connect + banner 断言 + extract 全过 → confirmed。
func TestRunTCPBannerPass(t *testing.T) {
	port := startTCPProbeServer(t, "-DENIED Roger...\r\nredis_version:7.2.4\r\n")
	pb := tcpPlaybook(t, port, `{connect_ok: true, banner_contains: ["redis_version"], banner_not_contains: ["MySQL"], banner_regex: "redis_version:[0-9.]+"}`)
	res, err := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "127.0.0.1"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("want confirmed, got %s (%s) steps=%+v", res.Verdict, res.Reason, res.Steps)
	}
	st := res.Steps[0]
	if st.Status != 1 || !strings.Contains(st.RespSnippet, "redis_version") {
		t.Fatalf("tcp 步观测留痕异常: status=%d snippet=%q", st.Status, st.RespSnippet)
	}
	if res.Extracted["redis_ver"] != "7.2.4" {
		t.Fatalf("banner 提取失败: %v", res.Extracted)
	}
	if res.Requests != 1 {
		t.Fatalf("请求数 = %d, want 1", res.Requests)
	}
}

// TestRunTCPBannerFail banner 断言不命中 → blocked（断言失败证据保留到失败步）。
func TestRunTCPBannerFail(t *testing.T) {
	port := startTCPProbeServer(t, "redis_version:7.2.4\r\n")
	pb := tcpPlaybook(t, port, `{connect_ok: true, banner_contains: ["MySQL"]}`)
	res, _ := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "127.0.0.1"}})
	if res.Verdict != VerdictBlocked {
		t.Fatalf("want blocked, got %s (%s)", res.Verdict, res.Reason)
	}
	if !strings.Contains(res.Steps[0].FailReason, "banner 不含") {
		t.Fatalf("失败原因应指向 banner 断言: %q", res.Steps[0].FailReason)
	}
}

// TestRunTCPConnectFailBlocked 连接失败（明确拒绝）+ connect_ok=true → blocked
// （网络错误≠测过，与 http 步同语义）。注入拨号桩保证「明确拒绝」确定性。
func TestRunTCPConnectFailBlocked(t *testing.T) {
	pb := tcpPlaybook(t, 6379, `{connect_ok: true}`)
	res, _ := Run(context.Background(), pb, RunOptions{
		Vars:      map[string]string{"host": "127.0.0.1"},
		TCPDialer: stubTCPDialer{err: refusedDialErr()},
	})
	if res.Verdict != VerdictBlocked {
		t.Fatalf("want blocked, got %s (%s)", res.Verdict, res.Reason)
	}
	if res.Steps[0].Status != 0 {
		t.Fatalf("连接失败步 Status 应为 0（未获观测）, got %d", res.Steps[0].Status)
	}
}

// TestRunTCPRefusedConfirmed connect_ok=false + 明确拒绝（RST）→ 端口关闭是
// 可观测结论 → confirmed（判「修复后端口已关」类假设）。注入拨号桩：真实回环
// 在部分 WSL2 宿主上不保证 RST 语义（见 stubTCPDialer 注释）。
func TestRunTCPRefusedConfirmed(t *testing.T) {
	pb := tcpPlaybook(t, 6379, `{connect_ok: false}`)
	res, _ := Run(context.Background(), pb, RunOptions{
		Vars:      map[string]string{"host": "127.0.0.1"},
		TCPDialer: stubTCPDialer{err: refusedDialErr()},
	})
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("want confirmed（端口明确关闭）, got %s (%s)", res.Verdict, res.Reason)
	}
}

// ── V2 dns（桩 resolver：平台侧 resolver 固定，测试注入替换）──

type stubDNSResolver struct {
	ips     []string
	cname   string
	txts    []string
	nss     []*net.NS
	hostErr error
}

func (s *stubDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return s.ips, s.hostErr
}
func (s *stubDNSResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return s.cname, nil
}
func (s *stubDNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return s.txts, nil
}
func (s *stubDNSResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return s.nss, nil
}

func dnsRun(t *testing.T, stub *stubDNSResolver, expect, extraSteps string, opts RunOptions) *RunResult {
	t.Helper()
	pb, err := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: dns_vocab
steps:
  - name: resolve_check
    kind: dns
    request: {query_name: "{{host}}", query_type: A}
    expect: %s
%s
`, expect, extraSteps)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.Vars == nil {
		opts.Vars = map[string]string{"host": "target.example.com"}
	}
	opts.Resolver = stub
	res, rerr := Run(context.Background(), pb, opts)
	if rerr != nil {
		t.Fatalf("run: %v", rerr)
	}
	return res
}

// TestRunDNSAssertions dns 断言面：resolve_contains 命中/不命中、NXDOMAIN 观测、
// CNAME 悬挂判据、记录数判据。
func TestRunDNSAssertions(t *testing.T) {
	// A 记录含目标网段 → confirmed
	res := dnsRun(t, &stubDNSResolver{ips: []string{"10.1.2.3", "10.1.2.4"}},
		`{resolve_contains: ["10.1.2."]}`, "", RunOptions{})
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("resolve_contains 命中应 confirmed, got %s (%s)", res.Verdict, res.Reason)
	}
	if !strings.Contains(res.Steps[0].RespSnippet, "10.1.2.3") {
		t.Fatalf("解析结果应留痕 RespSnippet: %+v", res.Steps[0])
	}

	// A 记录不含目标段 → blocked
	res = dnsRun(t, &stubDNSResolver{ips: []string{"10.1.2.3"}},
		`{resolve_contains: ["192.0.2."]}`, "", RunOptions{})
	if res.Verdict != VerdictBlocked || !strings.Contains(res.Steps[0].FailReason, "解析结果不含") {
		t.Fatalf("resolve_contains 不命中应 blocked: %s (%s)", res.Verdict, res.Steps[0].FailReason)
	}

	// NXDOMAIN（权威否定回答）也是可观测结论：0 条记录 → resolve_count_lt:1 过
	res = dnsRun(t, &stubDNSResolver{hostErr: &net.DNSError{Err: "no such host", Name: "target.example.com", IsNotFound: true}},
		`{resolve_count_lt: 1}`, "", RunOptions{})
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("NXDOMAIN 判据应 confirmed, got %s (%s)", res.Verdict, res.Reason)
	}

	// 记录数不少于阈值 → blocked
	res = dnsRun(t, &stubDNSResolver{ips: []string{"10.1.2.3", "10.1.2.4"}},
		`{resolve_count_lt: 1}`, "", RunOptions{})
	if res.Verdict != VerdictBlocked || !strings.Contains(res.Steps[0].FailReason, "未少于") {
		t.Fatalf("resolve_count_lt 不命中应 blocked: %s (%s)", res.Verdict, res.Steps[0].FailReason)
	}

	// CNAME 悬挂/接管判据
	pb, _ := LoadPlaybookFromBytes([]byte(`
id: dns_cname
steps:
  - name: cname_check
    kind: dns
    request: {query_name: "{{host}}", query_type: CNAME}
    expect: {cname_chain_contains: ["azurewebsites.net"]}
`))
	res, _ = Run(context.Background(), pb, RunOptions{
		Vars:     map[string]string{"host": "app.example.com"},
		Resolver: &stubDNSResolver{cname: "app.example.com.azurewebsites.net"},
	})
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("cname_chain_contains 命中应 confirmed, got %s (%s)", res.Verdict, res.Reason)
	}

	// TXT 记录判据
	pb, _ = LoadPlaybookFromBytes([]byte(`
id: dns_txt
steps:
  - name: txt_check
    kind: dns
    request: {query_name: "{{host}}", query_type: TXT}
    expect: {txt_contains: ["verify-token-123"]}
`))
	res, _ = Run(context.Background(), pb, RunOptions{
		Vars:     map[string]string{"host": "example.com"},
		Resolver: &stubDNSResolver{txts: []string{"verify-token-123"}},
	})
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("txt_contains 命中应 confirmed, got %s (%s)", res.Verdict, res.Reason)
	}
}

// TestRunDNSCountsTowardMaxRequests dns 查询计入 max_requests 硬顶（观测不豁免）。
func TestRunDNSCountsTowardMaxRequests(t *testing.T) {
	res := dnsRun(t, &stubDNSResolver{ips: []string{"10.1.2.3"}},
		`{resolve_contains: ["10.1.2."]}`, `
  - name: resolve_again
    kind: dns
    request: {query_name: "{{host}}", query_type: A}
    expect: {resolve_contains: ["10.1.2."]}
`, RunOptions{MaxRequests: 1})
	if res.Verdict != VerdictBlocked || res.Requests != 1 {
		t.Fatalf("dns 查询应计入硬顶: verdict=%s requests=%d", res.Verdict, res.Requests)
	}
	if !strings.Contains(res.Reason, "max_requests") {
		t.Fatalf("中止原因应指向 max_requests: %s", res.Reason)
	}
}

// ── V3：header 断言与时延差分（http 步）──

// TestRunHTTPHeaderAssertions resp_header_contains/regex 命中与不命中。
func TestRunHTTPHeaderAssertions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Verify-Proof", "yes")
		w.Header().Set("Set-Cookie", "sid=abc123; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	run := func(expect string) *RunResult {
		pb, _ := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: hdr_vocab
steps:
  - name: h
    request: {method: GET, url: "%s/"}
    expect: %s
`, srv.URL, expect)))
		res, _ := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "x"}})
		return res
	}

	if res := run(`{status: 200, resp_header_contains: ["X-Verify-Proof: yes", "Set-Cookie: sid="]}`); res.Verdict != VerdictConfirmed {
		t.Fatalf("header contains 命中应 confirmed, got %s (%s)", res.Verdict, res.Reason)
	}
	res := run(`{status: 200, resp_header_contains: ["X-Missing: 1"]}`)
	if res.Verdict != VerdictBlocked || !strings.Contains(res.Steps[0].FailReason, "响应头不含") {
		t.Fatalf("header contains 不命中应 blocked: %s (%s)", res.Verdict, res.Steps[0].FailReason)
	}
	if res := run(`{status: 200, resp_header_regex: "Set-Cookie: sid=[a-z0-9]+"}`); res.Verdict != VerdictConfirmed {
		t.Fatalf("header regex 命中应 confirmed, got %s (%s)", res.Verdict, res.Reason)
	}
	res = run(`{status: 200, resp_header_regex: "X-Missing: ."}`)
	if res.Verdict != VerdictBlocked || !strings.Contains(res.Steps[0].FailReason, "响应头不匹配正则") {
		t.Fatalf("header regex 不命中应 blocked: %s (%s)", res.Verdict, res.Steps[0].FailReason)
	}
}

// TestRunHTTPDurationAssertions duration_ms_lt/gt 时延差分命中与不命中
// （阈值两侧留足余量，避免计时毛刺导致偶发）。
func TestRunHTTPDurationAssertions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	run := func(path string, expect string) *RunResult {
		pb, _ := LoadPlaybookFromBytes([]byte(fmt.Sprintf(`
id: dur_vocab
steps:
  - name: d
    request: {method: GET, url: "%s%s"}
    expect: %s
`, srv.URL, path, expect)))
		res, _ := Run(context.Background(), pb, RunOptions{Vars: map[string]string{"host": "x"}})
		return res
	}

	// 慢端点耗时必 > 100ms → duration_ms_gt 命中
	if res := run("/slow", `{status: 200, duration_ms_gt: 100}`); res.Verdict != VerdictConfirmed {
		t.Fatalf("duration_ms_gt 命中应 confirmed, got %s (%s) duration=%d", res.Verdict, res.Reason, res.Steps[0].DurationMS)
	}
	// 快端点耗时必 < 5000ms → duration_ms_lt 命中
	if res := run("/fast", `{status: 200, duration_ms_lt: 5000}`); res.Verdict != VerdictConfirmed {
		t.Fatalf("duration_ms_lt 命中应 confirmed, got %s (%s)", res.Verdict, res.Reason)
	}
	// 慢端点（≥300ms）要求 < 100ms → 差分判据不命中 → blocked
	res := run("/slow", `{status: 200, duration_ms_lt: 100}`)
	if res.Verdict != VerdictBlocked || !strings.Contains(res.Steps[0].FailReason, "未低于") {
		t.Fatalf("duration_ms_lt 不命中应 blocked: %s (%s)", res.Verdict, res.Steps[0].FailReason)
	}
	// 快端点要求 > 10000ms → 不命中 → blocked
	res = run("/fast", `{status: 200, duration_ms_gt: 10000}`)
	if res.Verdict != VerdictBlocked || !strings.Contains(res.Steps[0].FailReason, "未高于") {
		t.Fatalf("duration_ms_gt 不命中应 blocked: %s (%s)", res.Verdict, res.Steps[0].FailReason)
	}
}
