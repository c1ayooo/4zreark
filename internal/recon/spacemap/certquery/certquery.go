// Package certquery 空间测绘引擎的证书组织（O=）反查能力注册表。
//
// 各引擎对证书 Subject Organization 检索的语法与精度不一致：
//
//	fofa    — cert.subject.org="Oracle Corporation"（专用字段，精确）
//	hunter  — cert.subject="Oracle Corporation"（专用字段，精确）
//	shodan  — ssl.cert.subject.O:"Oracle Corporation"（facet，精确）
//	quake   — cert:"Oracle Corporation"（证书全文匹配，含 Issuer/SAN，噪音高）
//	zoomeye — ssl="Oracle Corporation"（证书全文匹配，同上）
//
// 调用方（Agent 的 cert_expand 工具）不感知语法差异，只声明引擎名与组织名，
// 查询串构造统一走本包；行内域名/备案键提取复用 icpquery 的引擎行适配
// （cert→icp→company 三角互证）。新增引擎 = 追加一条 Capability 注册项。
package certquery

import (
	"fmt"
	"strings"
)

// MatchMode 反查精度语义。
type MatchMode string

const (
	// MatchExact 专用证书组织字段，语义精确。
	MatchExact MatchMode = "exact"
	// MatchContent 证书全文匹配（Subject/Issuer/SAN），会混入签发者/同名词命中。
	MatchContent MatchMode = "content"
)

// Key 一条反查线索：归一化后的证书组织名。
type Key struct {
	Value string
}

// ID 去重标识。
func (k Key) ID() string { return "org:" + k.Value }

// Capability 单个引擎的证书组织反查能力。OrgQuery 为 nil 表示不支持。
type Capability struct {
	Engine   string
	OrgQuery func(org string) string
	// MatchMode 命中语义（exact=专用字段；content=全文匹配，噪音高）。
	MatchMode MatchMode
	// UnsupportedReason 不支持的原因（OrgQuery 为 nil 时给用户看）。
	UnsupportedReason string
}

// capabilities 引擎注册表。遍历顺序：精确引擎在前（fofa/hunter/shodan），
// 内容匹配引擎在后（quake/zoomeye）——默认只取精确引擎。
var capabilities = map[string]*Capability{
	"fofa": {
		Engine:    "fofa",
		OrgQuery:  func(org string) string { return fmt.Sprintf(`cert.subject.org=%q`, org) },
		MatchMode: MatchExact,
	},
	"hunter": {
		Engine:    "hunter",
		OrgQuery:  func(org string) string { return fmt.Sprintf(`cert.subject=%q`, org) },
		MatchMode: MatchExact,
	},
	"shodan": {
		Engine:    "shodan",
		OrgQuery:  func(org string) string { return fmt.Sprintf(`ssl.cert.subject.O:%q`, org) },
		MatchMode: MatchExact,
	},
	"quake": {
		Engine:    "quake",
		OrgQuery:  func(org string) string { return fmt.Sprintf(`cert:%q`, org) },
		MatchMode: MatchContent,
	},
	"zoomeye": {
		Engine:    "zoomeye",
		OrgQuery:  func(org string) string { return fmt.Sprintf(`ssl=%q`, org) },
		MatchMode: MatchContent,
	},
}

// engineOrder 注册遍历顺序（精确在前）。
var engineOrder = []string{"fofa", "hunter", "shodan", "quake", "zoomeye"}

// Get 引擎能力；未注册引擎返回 nil。
func Get(engine string) *Capability {
	return capabilities[strings.ToLower(strings.TrimSpace(engine))]
}

// SupportedEngines 支持证书组织反查的引擎名列表（精确引擎在前）。
func SupportedEngines() []string {
	out := make([]string, 0, len(capabilities))
	for _, name := range engineOrder {
		if capabilities[name].OrgQuery != nil {
			out = append(out, name)
		}
	}
	return out
}

// ExactEngines 精确匹配引擎列表（cert_expand 的默认引擎集）。
func ExactEngines() []string {
	out := make([]string, 0, len(engineOrder))
	for _, name := range engineOrder {
		cap := capabilities[name]
		if cap.OrgQuery != nil && cap.MatchMode == MatchExact {
			out = append(out, name)
		}
	}
	return out
}

// AllEngines 全部已注册引擎名。
func AllEngines() []string {
	return append([]string(nil), engineOrder...)
}

// QueryFor 构造反查查询串。引擎不支持返回 ("", false)。
func QueryFor(engine, org string) (string, bool) {
	cap := Get(engine)
	if cap == nil || cap.OrgQuery == nil {
		return "", false
	}
	return cap.OrgQuery(org), true
}

// NormalizeOrg 组织名归一：去首尾空白、折叠连续空白（证书 DN 里的多空格与
// 用户输入对齐）。空串或过短（<3 rune）返回空串。
func NormalizeOrg(raw string) string {
	v := strings.Join(strings.Fields(raw), " ")
	if len([]rune(v)) < 3 {
		return ""
	}
	return v
}

// genericOrgs 高噪音通用主体组织（小写精确匹配）：这些组织的证书部署在
// 海量与目标无关的基础设施/客户设备上，反查会泛射出无意义的大结果集并
// 烧配额。可按需增删。
var genericOrgs = map[string]bool{
	// CDN / 云（证书随客户站点泛射）
	"cloudflare, inc.":                  true,
	"cloudflare inc":                    true,
	"google llc":                        true,
	"google inc.":                       true,
	"microsoft corporation":             true,
	"amazon":                            true,
	"amazon.com, inc.":                  true,
	"alibaba cloud computing ltd":       true,
	"alibaba (us) technology co., ltd.": true,
	// 网络设备厂商（默认证书随设备出厂，部署在客户网络）
	"cisco":                      true,
	"cisco systems, inc.":        true,
	"cisco systems inc.":         true,
	"f5 networks, inc.":          true,
	"f5, inc.":                   true,
	"fortinet, inc.":             true,
	"zyxel communications corp.": true,
	"qnap systems, inc.":         true,
	"synology inc.":              true,
	"siemens":                    true,
	"schneider electric":         true,
}

// GenericOrg 组织名是否命中通用主体黑名单（大小写不敏感；黑名单本身已归一）。
func GenericOrg(org string) bool {
	v := NormalizeOrg(org)
	return v != "" && genericOrgs[strings.ToLower(v)]
}

// CapabilitySummary 给 agent/前端的能力速览：每引擎反查语法样例与命中语义。
func CapabilitySummary() []map[string]interface{} {
	sample := "Oracle Corporation"
	out := make([]map[string]interface{}, 0, len(capabilities))
	for _, name := range engineOrder {
		cap := capabilities[name]
		if cap == nil {
			continue
		}
		item := map[string]interface{}{"engine": name}
		if cap.OrgQuery != nil {
			item["org"] = "支持（" + cap.OrgQuery(sample) + "）"
			if cap.MatchMode == MatchContent {
				item["match_mode"] = "content（证书全文匹配，含 Issuer/SAN，噪音高，建议行内备案互证）"
			} else {
				item["match_mode"] = "exact（证书组织专用字段，精确）"
			}
		} else {
			item["org"] = "不支持：" + cap.UnsupportedReason
		}
		out = append(out, item)
	}
	return out
}
