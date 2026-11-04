package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
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
	// ModePermissive 全放行——仅对应 ZRE_NOTIFY_ALLOW_PRIVATE=1 的历史语义
	// （内部服务 webhook 合法，含本机服务）与测试环境的本地模拟服务。
	ModePermissive
)

// envOverrideOnce 支撑测试逃生口：ZRE_SAFEHTTP_ALLOW_PRIVATE=1 时全放行。
// 仅测试进程使用（httptest 监听 127.0.0.1），生产部署不应设置该变量。
var (
	envOverrideOnce sync.Once
	envPermissive   bool
)

func envAllowsAll() bool {
	envOverrideOnce.Do(func() {
		envPermissive = os.Getenv("ZRE_SAFEHTTP_ALLOW_PRIVATE") == "1"
	})
	return envPermissive
}

// Forbidden 判定一个 IP 是否禁止直连。
func Forbidden(mode Mode, ip net.IP) bool {
	if mode == ModePermissive || envAllowsAll() {
		return false
	}
	if ip == nil {
		return true
	}
	// 所有模式都禁：未指定地址、环回、链路本地（含 169.254.169.254 云元数据）、组播
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// 运营商级 NAT 段：阿里云等环境的元数据服务 100.100.100.200 落在这里，
	// net.IP.IsPrivate 不覆盖，此前在 ModeScan 下可直连读元数据（审计 H-1）。
	if isCarrierNAT(ip) {
		return true
	}
	if mode == ModeStrict && ip.IsPrivate() {
		return true
	}
	return false
}

// cgnat 100.64.0.0/10（RFC 6598）。元数据地址 100.100.100.200 在其内。
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isCarrierNAT(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return cgnat.Contains(v4)
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

// NewProxyAwareDialer 返回「识别代理出口」的 Dialer。
//
// 走代理时 DialContext 看到的是代理地址，本机/内网代理（127.0.0.1:7890、
// 192.168.x.x:8080 这类最常见形态）会被 controlFor 当成 SSRF 目标直接拒绝，
// 结果是一旦配了代理，所有出网请求 100% 失败。这里对「环境变量里配置的代理
// 出口地址」放行，目标本身的校验交给调用方在请求侧用 CheckHost 前置完成。
func NewProxyAwareDialer(mode Mode, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: proxyAwareControlFor(mode),
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

// proxyAwareControlFor 在 controlFor 基础上放行代理出口地址。
func proxyAwareControlFor(mode Mode) func(network, address string, c syscall.RawConn) error {
	base := controlFor(mode)
	return func(network, address string, c syscall.RawConn) error {
		if isProxyEndpoint(address) {
			return nil
		}
		return base(network, address, c)
	}
}

// CheckHost 请求级目标校验：解析主机并拒绝落到受限地址的目标。
//
// 经代理出站时连接级 Control 只能看到代理地址，目标是否合法必须在发起请求前
// 单独判一次，否则代理会替我们把 SSRF 请求打到内网。
func CheckHost(mode Mode, host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("目标主机为空")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	}
	if ip := net.ParseIP(host); ip != nil {
		if Forbidden(mode, ip) {
			return fmt.Errorf("目标地址 %s 被安全策略拒绝（SSRF 防护）", host)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("解析目标主机 %s 失败: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("目标主机 %s 无解析结果", host)
	}
	for _, a := range addrs {
		if Forbidden(mode, a.IP) {
			return fmt.Errorf("目标主机 %s 解析到受限地址 %s（SSRF 防护）", host, a.IP)
		}
	}
	return nil
}

// 代理出口识别：把环境变量里的代理地址解析成 ip:port 集合，连接时命中即放行。
// 只认环境变量（HTTP_PROXY/HTTPS_PROXY/ALL_PROXY 及小写形式）——自定义代理
// 由调用方显式传入并自行决定是否可信。按端口精确匹配：同一个 IP 的其他端口
// 仍按受限地址处理，避免把 127.0.0.1 整台机器的服务都放出去。
var (
	proxyIPOnce  sync.Once
	proxyIPCache map[string]struct{}
)

func isProxyEndpoint(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	proxyIPOnce.Do(func() {
		proxyIPCache = map[string]struct{}{}
		for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
			raw := strings.TrimSpace(os.Getenv(key))
			if raw == "" {
				continue
			}
			if !strings.Contains(raw, "://") {
				raw = "http://" + raw
			}
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				continue
			}
			p := u.Port()
			if p == "" {
				p = "80"
				if u.Scheme == "https" {
					p = "443"
				}
			}
			h := u.Hostname()
			if pip := net.ParseIP(h); pip != nil {
				proxyIPCache[net.JoinHostPort(pip.String(), p)] = struct{}{}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx, h)
			cancel()
			if lerr != nil {
				continue
			}
			for _, a := range addrs {
				proxyIPCache[net.JoinHostPort(a.IP.String(), p)] = struct{}{}
			}
		}
	})
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	_, ok := proxyIPCache[net.JoinHostPort(host, port)]
	return ok
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

// WithSafeControl 给既有 Transport 补上连接级 SSRF 校验（审计 M3）：
// DialContext 为空时套安全 Dialer；Transport 配了代理函数时改用「代理感知」
// Dialer（放行代理出口自身），并把目标校验前置到 Proxy 函数——否则
// 127.0.0.1 上的本地代理会被当成 SSRF 目标，导致配了代理就全网失败。
// 调用方已自定义 DialContext 的由其自行负责校验。返回同一 Transport 便于链式。
func WithSafeControl(tr *http.Transport, timeout time.Duration) *http.Transport {
	if tr == nil {
		return tr
	}
	if tr.Proxy != nil {
		inner := tr.Proxy
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			u, err := inner(req)
			if err != nil {
				return nil, err
			}
			if herr := CheckHost(ModeScan, req.URL.Hostname()); herr != nil {
				return nil, herr
			}
			return u, nil
		}
		if tr.DialContext == nil {
			tr.DialContext = NewProxyAwareDialer(ModeScan, timeout).DialContext
		}
		return tr
	}
	if tr.DialContext == nil {
		tr.DialContext = NewDialer(ModeScan, timeout).DialContext
	}
	return tr
}
