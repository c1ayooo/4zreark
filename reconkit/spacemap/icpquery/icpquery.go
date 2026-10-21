// Package icpquery 空间测绘引擎的 ICP 反查能力注册表。
//
// 各引擎对"备案号/主办单位"检索的语法与数据维度不一致：
//
//	quake  — icp:"粤ICP备14006354号"          （colons 语法，中文双引号短语）
//	fofa   — icp="粤ICP备14006354号"、company="主办单位名"（等号语法）
//	zoomEye— 语法无 icp 过滤器（本平台集成的 host search 维度），不支持
//	shodan — 无中国备案数据源，不支持
//
// 调用方（Agent 的 icp_expand 工具、调度裂变 runFission）不感知语法差异，
// 只声明引擎名与键（备案号/主办单位），查询串构造与行内提取统一走本包。
// 新增引擎 = 追加一条 Capability 注册项。
package icpquery

import (
	"fmt"
	"strings"

	"github.com/c1ayooo/reconkit/fingerprint"
)

// KeyKind 裂变键类型：备案号 / 主办单位。
type KeyKind string

const (
	KindICP     KeyKind = "icp"
	KindCompany KeyKind = "company"
)

// Key 一条反查线索：kind + 归一化后的值。
type Key struct {
	Kind  KeyKind
	Value string
}

// ID 键去重标识。
func (k Key) ID() string { return string(k.Kind) + ":" + k.Value }

// Capability 单个引擎的 ICP 反查能力。查询函数为 nil 表示该引擎不支持对应键类型。
type Capability struct {
	Engine string
	// ICPQuery 备案号反查查询串模板（官方文档语法 icp:"…"）；nil = 不支持。
	ICPQuery func(icp string) string
	// CompanyQuery 主办单位反查查询串模板；nil = 不支持。
	CompanyQuery func(company string) string
	// UnsupportedReason ICP 反查不支持的原因（ICPQuery 为 nil 时给用户看）。
	UnsupportedReason string
	// ExtractKeys 从引擎返回行提取裂变键（值内部归一化：ICP 取主号）。
	ExtractKeys func(row map[string]interface{}) []Key
	// ExtractDomains 从引擎返回行提取域名候选（小写、去空）。
	ExtractDomains func(row map[string]interface{}) []string
}

// rowString 容错取字段：引擎行值可能是 string/float64/[]interface{} 等。
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

var capabilities = map[string]*Capability{
	"quake": {
		Engine:            "quake",
		ICPQuery:          func(icp string) string { return fmt.Sprintf(`icp:%q`, icp) },
		CompanyQuery:      nil, // Quake 无主办单位过滤器
		UnsupportedReason: "",
		ExtractKeys: func(row map[string]interface{}) []Key {
			var out []Key
			if icp := fingerprint.NormalizeICP(rowString(row, "icp")); icp != "" {
				out = append(out, Key{Kind: KindICP, Value: icp})
			}
			return out
		},
		ExtractDomains: func(row map[string]interface{}) []string {
			return normalizeDomains([]string{rowString(row, "domain"), rowString(row, "hostname")})
		},
	},
	"fofa": {
		Engine:       "fofa",
		ICPQuery:     func(icp string) string { return fmt.Sprintf(`icp=%q`, icp) },
		CompanyQuery: func(company string) string { return fmt.Sprintf(`company=%q`, company) },
		ExtractKeys: func(row map[string]interface{}) []Key {
			out := make([]Key, 0, 2)
			if icp := fingerprint.NormalizeICP(rowString(row, "icp")); icp != "" {
				out = append(out, Key{Kind: KindICP, Value: icp})
			}
			if c := rowString(row, "company"); c != "" {
				out = append(out, Key{Kind: KindCompany, Value: c})
			}
			return out
		},
		ExtractDomains: func(row map[string]interface{}) []string {
			return normalizeDomains([]string{rowString(row, "domain"), rowString(row, "host")})
		},
	},
	"zoomeye": {
		Engine:            "zoomeye",
		UnsupportedReason: "引擎语法无 icp 过滤器（host search 维度无备案数据）",
		ExtractKeys:       func(row map[string]interface{}) []Key { return nil },
		ExtractDomains: func(row map[string]interface{}) []string {
			return normalizeDomains([]string{rowString(row, "domain"), rowString(row, "hostname")})
		},
	},
	"hunter": {
		Engine: "hunter",
		// 鹰图备案号过滤器 icp.number；主办单位 icp.name（若与官方语法有出入，以
		// hunter 帮助文档为准调整模板即可）
		ICPQuery:     func(icp string) string { return fmt.Sprintf(`icp.number=%q`, icp) },
		CompanyQuery: func(company string) string { return fmt.Sprintf(`icp.name=%q`, company) },
		ExtractKeys: func(row map[string]interface{}) []Key {
			// openApi 返回行：number=ICP 备案号，company=主办单位
			out := make([]Key, 0, 2)
			if icp := fingerprint.NormalizeICP(rowString(row, "number", "icp")); icp != "" {
				out = append(out, Key{Kind: KindICP, Value: icp})
			}
			if c := rowString(row, "company"); c != "" {
				out = append(out, Key{Kind: KindCompany, Value: c})
			}
			return out
		},
		ExtractDomains: func(row map[string]interface{}) []string {
			// domain 优先；空则从 url 提取主机（normalizeDomains 剥 scheme/path/端口）
			if d := rowString(row, "domain"); d != "" {
				return normalizeDomains([]string{d})
			}
			return normalizeDomains([]string{rowString(row, "url")})
		},
	},
	"shodan": {
		Engine:            "shodan",
		UnsupportedReason: "引擎无中国 ICP 备案数据源",
		ExtractKeys:       func(row map[string]interface{}) []Key { return nil },
		ExtractDomains: func(row map[string]interface{}) []string {
			return normalizeDomains([]string{
				rowString(row, "hostnames"), rowString(row, "domains"), rowString(row, "hostname"),
			})
		},
	},
}

// Get 引擎能力；未注册引擎返回 nil。
func Get(engine string) *Capability {
	return capabilities[strings.ToLower(strings.TrimSpace(engine))]
}

// Supported 该引擎是否支持 ICP 备案号反查。
func Supported(engine string) bool {
	cap := Get(engine)
	return cap != nil && cap.ICPQuery != nil
}

// SupportedEngines 支持 ICP 反查的引擎名列表（注册顺序）。
func SupportedEngines() []string {
	out := make([]string, 0, len(capabilities))
	for _, name := range []string{"quake", "fofa", "hunter", "zoomeye", "shodan"} {
		if Supported(name) {
			out = append(out, name)
		}
	}
	return out
}

// AllEngines 全部已注册引擎名。
func AllEngines() []string {
	return []string{"quake", "fofa", "hunter", "zoomeye", "shodan"}
}

// QueryFor 构造反查查询串（官方主语法）。引擎或键类型不支持返回 ("", false)。
func QueryFor(engine string, kind KeyKind, value string) (string, bool) {
	cap := Get(engine)
	if cap == nil {
		return "", false
	}
	switch kind {
	case KindICP:
		if cap.ICPQuery == nil {
			return "", false
		}
		return cap.ICPQuery(value), true
	case KindCompany:
		if cap.CompanyQuery == nil {
			return "", false
		}
		return cap.CompanyQuery(value), true
	}
	return "", false
}

// KeysFromRows 批量提取裂变键（多行合并去重）。
func KeysFromRows(engine string, rows []map[string]interface{}) []Key {
	cap := Get(engine)
	if cap == nil || cap.ExtractKeys == nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]Key, 0, 4)
	for _, row := range rows {
		for _, k := range cap.ExtractKeys(row) {
			if k.Value == "" || seen[k.ID()] {
				continue
			}
			seen[k.ID()] = true
			out = append(out, k)
		}
	}
	return out
}

// DomainsFromRow 单行提取域名候选。
func DomainsFromRow(engine string, row map[string]interface{}) []string {
	cap := Get(engine)
	if cap == nil || cap.ExtractDomains == nil {
		return nil
	}
	return cap.ExtractDomains(row)
}

// CapabilitySummary 给 agent/前端的能力速览：每引擎支持的反查键与语法样例。
func CapabilitySummary() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(capabilities))
	for _, name := range AllEngines() {
		cap := Get(name)
		if cap == nil {
			continue
		}
		item := map[string]interface{}{"engine": name}
		if cap.ICPQuery != nil {
			item["icp"] = "支持（" + cap.ICPQuery("粤ICP备14006354号") + "）"
			if cap.CompanyQuery != nil {
				item["company"] = "支持"
			} else {
				item["company"] = "不支持"
			}
		} else {
			item["icp"] = "不支持：" + cap.UnsupportedReason
		}
		out = append(out, item)
	}
	return out
}
