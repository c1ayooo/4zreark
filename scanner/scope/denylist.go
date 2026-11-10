package scope

// 全局禁扫黑名单：与任务级授权边界（Scope）叠加的最后一道闸。
//
// 授权边界回答「目标是否在我的种子范围内」，黑名单回答「这个目标是否碰都不该碰」。
// 两者独立生效：黑名单命中一律拒绝，无论任务目标怎么写。配置来自 config.yaml
// 的 scanner.deny_domain_suffixes / scanner.deny_cidrs，master 与 worker 读同一
// 份配置，保证两端判定一致（worker 不连数据库，所以不走 KV 设置）。

import (
	"net"
	"net/netip"
	"strings"

	"github.com/c1ayooo/4zreark/config"
)

// DenyList 是解析后的禁扫黑名单。零值 = 不拦截任何目标。
type DenyList struct {
	suffixes []string
	prefixes []netip.Prefix
}

// ParseDenyList 构建黑名单；非法条目直接丢弃而不是报错——黑名单是保护性
// 配置，一条写错不应导致整个扫描器起不来。
func ParseDenyList(suffixes, cidrs []string) *DenyList {
	d := &DenyList{}
	for _, raw := range suffixes {
		s := strings.ToLower(strings.TrimSpace(raw))
		s = strings.TrimSuffix(s, ".")
		s = strings.TrimPrefix(s, "*.")
		if s != "" {
			d.suffixes = append(d.suffixes, s)
		}
	}
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		d.prefixes = append(d.prefixes, p.Masked())
	}
	return d
}

// DeniesHost 判断主机（域名或 IP）是否命中黑名单。允许 host:port 形式，端口自动剥离。
func (d *DenyList) DeniesHost(host string) bool {
	if d == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.ToLower(h)
	}
	for _, s := range d.suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, p := range d.prefixes {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// DeniesPrefix 判断网段是否整体落在某个禁扫网段内。
// 部分重叠不算覆盖——留给扫描期的逐主机判断处理。
func (d *DenyList) DeniesPrefix(p netip.Prefix) bool {
	if d == nil || len(d.prefixes) == 0 {
		return false
	}
	p = p.Masked()
	for _, dp := range d.prefixes {
		if dp.Bits() <= p.Bits() && dp.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// denyFromConfig 读全局配置构建黑名单。配置未加载（单测等场景）时返回空黑名单。
func denyFromConfig() *DenyList {
	c := config.Loaded()
	if c == nil {
		return &DenyList{}
	}
	return ParseDenyList(c.Scanner.DenyDomainSuffixes, c.Scanner.DenyCIDRs)
}
