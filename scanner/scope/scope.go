// Package scope 定义一次扫描的授权边界：只允许任务 targets 覆盖的主机。
//
//   - 域名：本身 + 所有子域
//   - CIDR：网段内 IP
//   - IP：精确匹配
//
// 空 scope（没有可解析的 target）视为「未配置」，放行；调用方应在创建任务时
// 校验 targets 非空，因此这只作为容错。
package scope

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type Scope struct {
	domains  []string
	exactIP  map[string]bool
	prefixes []netip.Prefix
}

func New(targets []string) *Scope {
	s := &Scope{exactIP: map[string]bool{}}
	for _, raw := range targets {
		host := normalizeTarget(raw)
		if host == "" {
			continue
		}
		if strings.Contains(host, "/") {
			if p, err := netip.ParsePrefix(host); err == nil {
				s.prefixes = append(s.prefixes, p)
				continue
			}
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			s.exactIP[ip.String()] = true
			continue
		}
		host = strings.TrimPrefix(host, "*.")
		host = strings.Trim(host, ".")
		if host != "" {
			s.domains = append(s.domains, strings.ToLower(host))
		}
	}
	return s
}

// AllowsHost 判断主机是否在授权范围内。空 scope 放行。
func (s *Scope) AllowsHost(host string) bool {
	if s == nil || (len(s.domains) == 0 && len(s.exactIP) == 0 && len(s.prefixes) == 0) {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	// 去掉可能残留的端口
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.ToLower(h)
	}
	if s.exactIP[host] {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, p := range s.prefixes {
			if p.Contains(ip) {
				return true
			}
		}
	}
	for _, d := range s.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// AllowsURL 从 URL 提取 host 后判断。
func (s *Scope) AllowsURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if !strings.Contains(raw, "://") {
		return s.AllowsHost(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return s.AllowsHost(u.Hostname())
}

func normalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			return u.Hostname()
		}
	}
	raw = strings.TrimSuffix(raw, "/")
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		// CIDR 的 "/" 要保留；只有路径才截断
		if !strings.Contains(raw[:i], ":") && strings.Count(raw, "/") == 1 {
			if _, err := netip.ParsePrefix(raw); err == nil {
				return raw
			}
		}
		return raw[:i]
	}
	return raw
}
