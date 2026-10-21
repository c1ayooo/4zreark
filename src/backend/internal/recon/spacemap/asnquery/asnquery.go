// Package asnquery 空间测绘引擎的 ASN/BGP 反查能力注册表。
//
// 各引擎对 ASN/CIDR/Organization 检索的语法不一致：
//
//	quake   — asn:"AS15169"
//	fofa    — asn="AS15169"、org="Google Inc."
//	zoomeye — asn=AS15169
//	hunter  — ip.asn=AS15169
//	shodan  — org:Google Inc.（无直接 ASN 过滤语法）
//
// 调用方（Agent 的 asn_expand 工具）不感知语法差异，只声明引擎名与键（ASN/网段/机构），
// 查询串构造与行内提取统一走本包。新增引擎 = 追加一条 Capability 注册项。
package asnquery

import (
	"fmt"
	"strings"
)

// KeyKind 反查键类型。
type KeyKind string

const (
	KindASN  KeyKind = "asn"  // "AS15169"
	KindCIDR KeyKind = "cidr" // "15169.0.0.0/8"
	KindOrg  KeyKind = "org"  // "Google Inc."
)

// Key 一条反查线索。
type Key struct {
	Kind  KeyKind
	Value string
}

// ID 去重标识。
func (k Key) ID() string { return string(k.Kind) + ":" + k.Value }

// Capability 单个引擎的 ASN 反查能力。
type Capability struct {
	Engine            string
	ASNQuery          func(asn string) string  // nil = 不支持
	CIDRQuery         func(cidr string) string // nil = 不支持
	OrgQuery          func(org string) string  // nil = 不支持
	UnsupportedReason string
	ExtractHosts      func(row map[string]interface{}) []string
	ExtractDomains    func(row map[string]interface{}) []string
}

// capabilities 引擎注册表（按固定顺序遍历）。
var capabilities = map[string]*Capability{
	"quake": {
		Engine: "quake",
		ASNQuery: func(asn string) string {
			return fmt.Sprintf("asn:%q", asn)
		},
		OrgQuery: nil,
		ExtractDomains: func(row map[string]interface{}) []string {
			return normalizeDomains([]string{
				rowString(row, "domain", "hostname", "host"),
			})
		},
		ExtractHosts: func(row map[string]interface{}) []string {
			return extractHostList(row, "ip", "host")
		},
	},
	"fofa": {
		Engine: "fofa",
		ASNQuery: func(asn string) string {
			return fmt.Sprintf("asn=%q", asn)
		},
		CIDRQuery: func(cidr string) string {
			return fmt.Sprintf("net=%q", cidr)
		},
		OrgQuery: func(org string) string {
			return fmt.Sprintf("org=%q", org)
		},
		ExtractDomains: func(row map[string]interface{}) []string {
			return normalizeDomains([]string{
				rowString(row, "domain", "host"),
			})
		},
		ExtractHosts: func(row map[string]interface{}) []string {
			return extractHostList(row, "ip", "host")
		},
	},
	"zoomeye": {
		Engine: "zoomeye",
		ASNQuery: func(asn string) string {
			return "asn=" + strings.TrimSpace(asn)
		},
		OrgQuery: func(org string) string {
			return "org=" + org
		},
		ExtractDomains: func(row map[string]interface{}) []string {
			return normalizeDomains([]string{
				rowString(row, "domain", "hostname"),
			})
		},
		ExtractHosts: func(row map[string]interface{}) []string {
			return extractHostList(row, "ip", "host")
		},
	},
	"hunter": {
		Engine: "hunter",
		ASNQuery: func(asn string) string {
			// hunter ip.asn=AS15169；若传入纯数字，自动补 AS 前缀
			return fmt.Sprintf("ip.asn=%q", normalizeASN(asn))
		},
		OrgQuery: func(org string) string {
			return fmt.Sprintf("icp.name=%q", org)
		},
		ExtractDomains: func(row map[string]interface{}) []string {
			if d := rowString(row, "domain"); d != "" {
				return normalizeDomains([]string{d})
			}
			return normalizeDomains([]string{rowString(row, "url")})
		},
		ExtractHosts: func(row map[string]interface{}) []string {
			return extractHostList(row, "ip")
		},
	},
	"shodan": {
		Engine:            "shodan",
		UnsupportedReason: "shodan 无直接 ASN 查询语法（可用 net=CIDR 替代，由调用方用 fofa/zoomeye 覆盖）",
	},
}

func normalizeASN(asn string) string {
	asn = strings.TrimSpace(asn)
	if strings.HasPrefix(strings.ToUpper(asn), "AS") {
		return strings.ToUpper(asn)
	}
	return "AS" + asn
}

// rowString 容错取字段。
func rowString(row map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		switch v := row[k].(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		case float64:
			return fmt.Sprint(v)
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					if s = strings.TrimSpace(s); s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

// extractHostList 从行中提取 IP/主机列表（逗号/分号/空格分隔均兼容）。
func extractHostList(row map[string]interface{}, keys ...string) []string {
	var raw []string
	for _, k := range keys {
		if s := rowString(row, k); s != "" {
			raw = append(raw, s)
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range raw {
		for _, part := range strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\n'
		}) {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

// normalizeDomains 域名候选规整：小写、剥 scheme/路径/端口、去重。
func normalizeDomains(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		d := strings.ToLower(strings.TrimSpace(v))
		d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
		if i := strings.IndexByte(d, '/'); i > 0 {
			d = d[:i]
		}
		if i := strings.IndexByte(d, ':'); i > 0 {
			d = d[:i]
		}
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ── 公开 API ──

// Get 引擎能力；未注册引擎返回 nil。
func Get(engine string) *Capability {
	return capabilities[strings.ToLower(strings.TrimSpace(engine))]
}

// Supported 该引擎是否支持 ASN 反查（至少一种查询函数非 nil）。
func Supported(engine string) bool {
	cap := Get(engine)
	if cap == nil || cap.ASNQuery == nil && cap.CIDRQuery == nil && cap.OrgQuery == nil {
		return false
	}
	return true
}

// SupportedEngines 支持 ASN 反查的引擎名列表（注册顺序）。
func SupportedEngines() []string {
	out := []string{}
	for _, name := range AllEngines() {
		if Supported(name) {
			out = append(out, name)
		}
	}
	return out
}

// AllEngines 全部已注册引擎。
func AllEngines() []string { return []string{"quake", "fofa", "zoomeye", "hunter", "shodan"} }

// QueryFor 构造反查查询串。引擎或键类型不支持返回 ("", false)。
func QueryFor(engine string, kind KeyKind, value string) (string, bool) {
	cap := Get(engine)
	if cap == nil {
		return "", false
	}
	switch kind {
	case KindASN:
		if cap.ASNQuery == nil {
			return "", false
		}
		return cap.ASNQuery(value), true
	case KindCIDR:
		if cap.CIDRQuery == nil {
			return "", false
		}
		return cap.CIDRQuery(value), true
	case KindOrg:
		if cap.OrgQuery == nil {
			return "", false
		}
		return cap.OrgQuery(value), true
	}
	return "", false
}

// DomainsFromRow 单行提取域名候选。
func DomainsFromRow(engine string, row map[string]interface{}) []string {
	cap := Get(engine)
	if cap == nil || cap.ExtractDomains == nil {
		return nil
	}
	return cap.ExtractDomains(row)
}

// HostsFromRow 单行提取 IP 列表。
func HostsFromRow(engine string, row map[string]interface{}) []string {
	cap := Get(engine)
	if cap == nil || cap.ExtractHosts == nil {
		return nil
	}
	return cap.ExtractHosts(row)
}

// ASNsFromRow 单行提取 ASN 键（asn_expand 的下一层展开素材；引擎行里 asn 字段名不一）。
func ASNsFromRow(engine string, row map[string]interface{}) []Key {
	raw := rowString(row, "asn", "ASN", "q_asn", "ip.asn")
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Key
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n'
	}) {
		part = normalizeASN(part)
		if part == "AS" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, Key{Kind: KindASN, Value: part})
	}
	return out
}
