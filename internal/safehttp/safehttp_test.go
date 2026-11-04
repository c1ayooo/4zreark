package safehttp

import (
	"net"
	"sync"
	"testing"
)

// 审计 M3 验收：rebinding 后的第二次解析（loopback）在连接层被拒绝；
// 云元数据地址在所有模式下被禁；内网资产在 ModeScan 下放行、ModeStrict 下拒绝。
func TestForbidden(t *testing.T) {
	cases := []struct {
		ip           string
		scanAllowed  bool
		strictAllowd bool
	}{
		{"127.0.0.1", false, false},              // loopback
		{"::1", false, false},                    // IPv6 loopback
		{"169.254.169.254", false, false},        // 云元数据（AWS/GCP/Azure）
		{"169.254.1.1", false, false},            // 链路本地段其余地址
		{"0.0.0.0", false, false},                // 未指定
		{"10.1.2.3", true, false},                // 内网资产：探测放行，凭据出站拒绝
		{"192.168.1.10", true, false},            // 同上
		{"172.16.0.9", true, false},              // 同上
		{"100.64.0.1", false, false},             // CGNAT 100.64/10（审计 H-1：此前放行）
		{"100.100.100.200", false, false},        // 阿里云元数据，落在 CGNAT 段内
		{"100.127.255.254", false, false},        // CGNAT 上边界
		{"100.128.0.1", true, true},              // /10 之外，属公网
		{"224.0.0.1", false, false},              // 组播
		{"8.8.8.8", true, true},                  // 公网
		{"fe80::1", false, false},                // IPv6 链路本地
		{"fd00::1", true, false},                 // IPv6 ULA 算私网
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if got := Forbidden(ModeScan, ip); got != !c.scanAllowed {
			t.Fatalf("ModeScan(%s) = %v, 期望拒绝=%v", c.ip, got, !c.scanAllowed)
		}
		if got := Forbidden(ModeStrict, ip); got != !c.strictAllowd {
			t.Fatalf("ModeStrict(%s) = %v, 期望拒绝=%v", c.ip, got, !c.strictAllowd)
		}
	}
	if Forbidden(ModeScan, nil) != true {
		t.Fatalf("nil IP 应拒绝")
	}
	// Permissive 档（历史逃生口语义）：全放行
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "8.8.8.8"} {
		if Forbidden(ModePermissive, net.ParseIP(ip)) {
			t.Fatalf("Permissive(%s) 应放行", ip)
		}
	}
}

// 连接级校验：非 IP 目标拒绝（伪造的 Dialer 调用不经 Transport 解析）。
func TestNewDialerRejectsNonIP(t *testing.T) {
	d := NewDialer(ModeStrict, 0)
	if err := d.Control("tcp", "example.com:443", nil); err == nil {
		t.Fatalf("非 IP 目标应被拒绝")
	}
	if err := d.Control("tcp", "127.0.0.1:8080", nil); err == nil {
		t.Fatalf("loopback 应被拒绝")
	}
	if err := d.Control("tcp", "10.0.0.5:80", nil); err == nil {
		t.Fatalf("strict 模式私网应被拒绝")
	}
	scan := NewDialer(ModeScan, 0)
	if err := scan.Control("tcp", "10.0.0.5:80", nil); err != nil {
		t.Fatalf("scan 模式内网资产应放行: %v", err)
	}
}

// 代理感知 Dialer：环境变量里的代理出口豁免连接级校验，其他受限地址照旧拒绝。
func TestProxyAwareDialer(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:43433")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:43433")
	resetProxyCache()
	defer resetProxyCache()

	d := NewProxyAwareDialer(ModeScan, 0)
	if err := d.Control("tcp", "127.0.0.1:43433", nil); err != nil {
		t.Fatalf("配置的代理出口应放行: %v", err)
	}
	if err := d.Control("tcp", "127.0.0.1:6379", nil); err == nil {
		t.Fatalf("非代理端口的 loopback 仍应拒绝")
	}
	if err := d.Control("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatalf("云元数据仍应拒绝")
	}
	// 未配置代理时行为回到普通 Dialer
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	resetProxyCache()
	if err := NewProxyAwareDialer(ModeScan, 0).Control("tcp", "127.0.0.1:43433", nil); err == nil {
		t.Fatalf("无代理配置时 loopback 应拒绝")
	}
}

// CheckHost：请求级目标校验（走代理时唯一的目标闸口）。
func TestCheckHost(t *testing.T) {
	if err := CheckHost(ModeScan, "127.0.0.1"); err == nil {
		t.Fatalf("loopback 应拒绝")
	}
	if err := CheckHost(ModeScan, "100.100.100.200"); err == nil {
		t.Fatalf("云元数据（CGNAT）应拒绝")
	}
	if err := CheckHost(ModeScan, ""); err == nil {
		t.Fatalf("空主机应拒绝")
	}
	if err := CheckHost(ModeScan, "8.8.8.8"); err != nil {
		t.Fatalf("公网 IP 应放行: %v", err)
	}
	if err := CheckHost(ModePermissive, "127.0.0.1"); err != nil {
		t.Fatalf("Permissive 应放行: %v", err)
	}
}

// resetProxyCache 让测试可以重算代理出口集合（生产只在首次调用时读环境变量）。
func resetProxyCache() {
	proxyIPOnce = sync.Once{}
	proxyIPCache = nil
}
