package service

import (
	"os"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 探测逻辑的单元测试以 httptest（127.0.0.1）为目标；连接级 SSRF 校验在生产
// 禁 loopback，测试进程显式放行（仅本测试二进制生效）。
func init() { os.Setenv("ZRE_SAFEHTTP_ALLOW_PRIVATE", "1") }


// 403/404/500 也算连通：只要拿到 HTTP 响应，就证明这个入口还活着。
func TestProbeReachableStatuses(t *testing.T) {
	ctx := context.Background()
	for _, code := range []int{200, 301, 403, 404, 500} {
		code := code
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		host, portStr, _ := net.SplitHostPort(u.Host)
		port, _ := strconv.Atoi(portStr)

		res := ProbeEndpoint(ctx, host, port, "http")
		srv.Close()

		if res.Outcome != ProbeReachable {
			t.Fatalf("状态码 %d：期望 reachable，得到 %s（%s）", code, res.Outcome, res.Detail)
		}
		if res.StatusCode != code {
			t.Fatalf("状态码 %d：StatusCode 记录成 %d", code, res.StatusCode)
		}
		wantReason := "http_ok"
		if code >= 400 {
			wantReason = "http_error"
		}
		if res.ReasonCode != wantReason {
			t.Fatalf("状态码 %d：reason 期望 %s，得到 %s", code, wantReason, res.ReasonCode)
		}
	}
}

// 端口没开 = conn_fail（不是超时，也不能算「不确定」）
func TestProbeConnFail(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	res := ProbeEndpoint(context.Background(), "127.0.0.1", port, "http")
	if res.Outcome != ProbeConnFail {
		t.Fatalf("期望 conn_fail，得到 %s（%s）", res.Outcome, res.Detail)
	}
}

// 人为让域名解析进 fake-ip 段：必须判「不确定」，不能计失败
func TestProbeFakeIPIsInconclusive(t *testing.T) {
	old := resolveIPAddr
	defer func() { resolveIPAddr = old }()
	resolveIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.IPv4(198, 18, 0, 7)}}, nil
	}

	res := ProbeEndpoint(context.Background(), "anything.example.com", 443, "https")
	if res.Outcome != ProbeInconclusive || res.ReasonCode != "fake_ip" {
		t.Fatalf("期望 inconclusive/fake_ip，得到 %s/%s", res.Outcome, res.ReasonCode)
	}
	if res.Reachable() {
		t.Fatal("fake_ip 不该被当成可达")
	}
}

// 公网域名解析到私网地址：同样判「不确定」
func TestProbePrivateAddrIsInconclusive(t *testing.T) {
	old := resolveIPAddr
	defer func() { resolveIPAddr = old }()
	resolveIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.IPv4(10, 1, 2, 3)}}, nil
	}

	res := ProbeEndpoint(context.Background(), "internal.example.com", 443, "https")
	if res.Outcome != ProbeInconclusive || res.ReasonCode != "private_addr" {
		t.Fatalf("期望 inconclusive/private_addr，得到 %s/%s", res.Outcome, res.ReasonCode)
	}
}

// 裸 IP 属于私网时仍然照常探测：用户显式导入的 IP 不该被当成污染
func TestProbeBarePrivateIPStillProbed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	res := ProbeEndpoint(context.Background(), "127.0.0.1", port, "http")
	if res.Outcome == ProbeInconclusive {
		t.Fatal("裸 IP 不该被判成不确定")
	}
}

// 域名解析失败 = dns_fail，要计失败
func TestProbeDNSFail(t *testing.T) {
	old := resolveIPAddr
	defer func() { resolveIPAddr = old }()
	resolveIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("no such host")
	}

	res := ProbeEndpoint(context.Background(), "no-such-host.invalid", 443, "https")
	if res.Outcome != ProbeDNSFail {
		t.Fatalf("期望 dns_fail，得到 %s（%s）", res.Outcome, res.Detail)
	}
}

// 整条链路对真实站点的兜底：连不上时要限时返回，不能挂住
func TestProbeTimeoutBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	// 保留地址段，必然连不通；只验证「有时限地返回」
	res := ProbeEndpoint(ctx, "192.0.2.1", 443, "https")
	if elapsed := time.Since(start); elapsed > 14*time.Second {
		t.Fatalf("探测没有被超时约束，耗时 %s", elapsed)
	}
	if res.Outcome == ProbeReachable {
		t.Fatalf("保留地址段不该判可达")
	}
}

// 桌面 UA 被 WAF 403 时，用手机 UA 回退；拿到 200 就采用手机端结果。
func TestProbeFallsBackToMobileUA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "Android") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><title>mobile</title></html>"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("desktop blocked"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	res := ProbeEndpoint(context.Background(), "127.0.0.1", port, "http")
	if !res.Reachable() || res.StatusCode != http.StatusOK {
		t.Fatalf("手机 UA 回退未生效: %+v", res)
	}
	if res.Detail != "mobile_ua" || !strings.Contains(res.Body, "mobile") {
		t.Fatalf("应使用手机端响应: %+v", res)
	}
}
