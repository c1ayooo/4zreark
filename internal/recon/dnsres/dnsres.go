// Package dnsres 纯 Go DNS 解析层：解析器池（自定义 DNS 服务器 + 并发上限 +
// 重试）、A/CNAME 解析与泛解析检测。对应 srcradar 的 dnsx + check_wildcard 职责，
// 但全部用标准库 net.Resolver 实现，零外部二进制。
package dnsres

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultServers 内置公共解析器（按延迟经验排序，快→慢；可在设置页覆盖）。
var DefaultServers = []string{
	"223.5.5.5",    // AliDNS
	"119.29.29.29", // DNSPod
	"114.114.114.114",
	"180.76.76.76", // Baidu
	"8.8.8.8",      // Google
	"1.1.1.1",      // Cloudflare
}

// Answer 单个主机名的解析结论。
type Answer struct {
	Host     string   // 查询名（小写、去尾点）
	IPs      []string // A/AAAA 记录（IPv4 优先）
	CNAME    string   // 首个 CNAME 链目标（无则空）
	NXDomain bool     // 权威 NXDOMAIN
}

// Pool 解析器池：多服务器轮转 + 全局并发上限 + 每查询超时重试。
type Pool struct {
	servers     []string
	concurrency chan struct{}
	timeout     time.Duration
	retries     int
	mu          sync.Mutex
	next        int
}

// NewPool 创建解析池。servers 为空时使用 DefaultServers。
// concurrency<=0 时按 32 兜底；timeout<=0 按 3s；retries<1 按 2。
func NewPool(servers []string, concurrency int, timeout time.Duration, retries int) *Pool {
	if len(servers) == 0 {
		servers = DefaultServers
	}
	cleaned := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" || strings.ContainsAny(s, " /\\") {
			continue // 空条目 / 明显非法（含空格或路径分隔符）直接丢弃
		}
		if !strings.Contains(s, ":") {
			s += ":53"
		}
		cleaned = append(cleaned, s)
	}
	if len(cleaned) == 0 {
		cleaned = DefaultServers
	}
	if concurrency <= 0 {
		concurrency = 32
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if retries < 1 {
		retries = 2
	}
	return &Pool{servers: cleaned, concurrency: make(chan struct{}, concurrency), timeout: timeout, retries: retries}
}

func (p *Pool) nextServer() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.servers[p.next%len(p.servers)]
	p.next++
	return s
}

// resolverFor 构造指向指定服务器的纯 Go resolver。
// PreferGo 必须开：cgo 解析器不支持自定义 Dial 指向任意服务器。
func resolverFor(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, server)
		},
	}
}

// Resolve 解析主机名的 A/AAAA + CNAME。全部尝试失败时返回 error；
// 明确 NXDOMAIN 时返回 Answer{NXDomain: true} 与 nil error。
func (p *Pool) Resolve(ctx context.Context, host string) (*Answer, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, fmt.Errorf("空主机名")
	}
	var lastErr error
	for attempt := 0; attempt < p.retries; attempt++ {
		server := p.nextServer()
		select {
		case p.concurrency <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		answer, err := p.resolveOnce(ctx, server, host)
		<-p.concurrency
		if err == nil {
			return answer, nil
		}
		if isNXDomain(err) {
			// 悬挂 CNAME 信号保留：CNAME 在但目标侧无 A 记录，是子域接管
			// 检测（takeover 包）的输入，调用方按 Answer.CNAME 非空区分
			// 真消失域名与 dangling 引用。
			if answer == nil {
				answer = &Answer{Host: host}
			}
			answer.NXDomain = true
			return answer, nil
		}
		lastErr = err
		// 换服务器前小退避，避免对同一台被打挂的解析器连续重试
		select {
		case <-time.After(time.Duration(attempt+1) * 200 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("解析失败")
	}
	return nil, fmt.Errorf("解析 %s 失败: %w", host, lastErr)
}

func (p *Pool) resolveOnce(ctx context.Context, server, host string) (*Answer, error) {
	rctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	r := resolverFor(server)
	answer := &Answer{Host: host}
	cnames, err := r.LookupCNAME(rctx, host)
	if err == nil && cnames != "" {
		cname := strings.TrimSuffix(strings.ToLower(cnames), ".")
		if cname != host && cname != "" {
			answer.CNAME = cname
		}
	}
	addrs, err := r.LookupHost(rctx, host)
	if err != nil {
		if isNXDomain(err) || isNoSuchHost(err) {
			// answer 随错误一起带回（内含已收集的 CNAME），见 Resolve 的悬挂语义
			return answer, errNXDomain
		}
		return answer, err
	}
	// IPv4 优先，IPv6 附后
	ipv4, ipv6 := make([]string, 0, len(addrs)), make([]string, 0)
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip.String())
		} else {
			ipv6 = append(ipv6, ip.String())
		}
	}
	answer.IPs = append(ipv4, ipv6...)
	if len(answer.IPs) == 0 {
		return answer, errNXDomain
	}
	return answer, nil
}

var errNXDomain = fmt.Errorf("NXDOMAIN")

func isNXDomain(err error) bool { return err == errNXDomain }

// isNoSuchHost 兼容 Go 1.20+ 的 DNSError.IsNotFound 语义（各版本字段不同，按字符串兜底）。
func isNoSuchHost(err error) bool {
	type noSuchHoster interface{ IsNotFound() bool }
	if n, ok := err.(noSuchHoster); ok {
		return n.IsNotFound()
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

// WildcardResult 泛解析检测结论。IPs 为随机子域解析出的 IP 集合——
// 后续候选若解析到同一批 IP，视为泛解析命中。
type WildcardResult struct {
	IsWildcard bool
	IPs        map[string]bool
}

// DetectWildcard 对主域做泛解析探测：把随机 label 子域送解析，
// 命中比例 ≥ 阈值（默认 3 次探测 2 次解析成功）判定开启泛解析。
// srcradar check_wildcard 同语义。
func (p *Pool) DetectWildcard(ctx context.Context, domain string, probes int) (*WildcardResult, error) {
	if probes <= 0 {
		probes = 3
	}
	result := &WildcardResult{IPs: map[string]bool{}}
	resolved := 0
	for i := 0; i < probes; i++ {
		label := randomLabel()
		answer, err := p.Resolve(ctx, label+"."+domain)
		if err != nil {
			continue
		}
		if len(answer.IPs) > 0 {
			resolved++
			for _, ip := range answer.IPs {
				result.IPs[ip] = true
			}
		}
	}
	if resolved*2 >= probes { // ≥50% 命中即判定（3 探 2 中 / 4 探 2 中）
		result.IsWildcard = true
	}
	return result, nil
}

const labelAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomLabel() string {
	b := make([]byte, 12)
	for i := range b {
		b[i] = labelAlphabet[rand.Intn(len(labelAlphabet))]
	}
	return string(b)
}
