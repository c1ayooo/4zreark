package safehttp

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// 安全审计 M3：SSRF 防护下沉到「实际连接」。
//
// 此前的模式是「先解析校验、后拨号」——两次解析之间存在 DNS rebinding 窗口，
// 且重定向/多入口不会重复校验。这里把校验放进 DialContext：Transport 拨号前
// 拿到的已是解析后的目标 IP，每个连接（含重定向的每一跳）都逃不过同一份
// 判定；TLS 层不受影响（ServerName 仍取 URL 原始 host）。
//
// 两档模式：
//   - ModeStrict：凭据出站（Webhook、GitHub 凭据测试等）——在 ModeScan 基础上
//     再禁 RFC1918 私网，与 webhook URL 前置校验同一策略；
//   - ModeScan：资产探测/监控/上游资源下载——内网资产是授权范围内的合法目标，
//     但 loopback / 云元数据（169.254.0.0/16 链路本地段）/ 未指定 / 组播一律禁止。
//
// 经代理出站时 DialContext 看到的是代理地址，逐跳校验由代理的出口策略承接；
// URL 级前置校验（scheme/host 白名单）仍然保留，两层叠加。

type Mode int

const (
	ModeScan Mode = iota
	ModeStrict
)

// Forbidden 判定一个 IP 是否禁止直连。
func Forbidden(mode Mode, ip net.IP) bool {
	if ip == nil {
		return true
	}
	// 所有模式都禁：未指定地址、环回、链路本地（含 169.254.169.254 云元数据）、组播
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if mode == ModeStrict && ip.IsPrivate() {
		return true
	}
	return false
}

// NewDialer 返回带连接级校验的 Dialer。
func NewDialer(mode Mode, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: controlFor(mode),
	}
}

// controlFor 用 Dialer.Control 在 connect 系统调用前校验对端地址——
// 比 DialContext 更底层，NAT/解析器差异都绕不过。
func controlFor(mode Mode) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("连接地址无效 %q: %w", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("连接目标不是 IP: %q", address)
		}
		if Forbidden(mode, ip) {
			return fmt.Errorf("目标地址 %s 被安全策略拒绝（SSRF 防护）", address)
		}
		return nil
	}
}

// Client 返回统一安全 HTTP 客户端：连接级校验 + 禁跟随重定向到被拒地址
// （重定向每一跳都会重新拨号，Control 校验天然逐跳生效）。
func Client(mode Mode, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       NewDialer(mode, timeout).DialContext,
			DisableKeepAlives: true,
		},
	}
}
