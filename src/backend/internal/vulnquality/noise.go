package vulnquality

import "strings"

// noise_cap.go —— D6-2 扫描器噪音降级（docs/archive/渗透Agent能力缺口-五层框架对照与补齐施工单.md D6-2）。
//
// 对治病根：指纹/扫描器把「SSL 证书过期、缺失安全头、版本信息泄露」这类低证据
// 配置噪音也报成 high/critical。降级规则是**显式类型关键词清单**（不做「按关键词猜」），
// 命中则 severity 封顶为 low/info，需真实证据（可复现/已确认）才允许升级。
// 只影响漏洞记录的严重级（展示/排序面），不参与任何拦截/放行决策。

// NoiseSeverityCap 低证据噪音类型的 severity 封顶档位。
type NoiseSeverityCap struct {
	Keywords []string // 类型/标题关键词（全部小写匹配，显式枚举）
	Cap      string   // 封顶严重级：low / info
}

// NoiseCaps 显式噪音降级清单（D6-2）。新增条目必须逐个核准，禁止通配。
var NoiseCaps = []NoiseSeverityCap{
	{
		Keywords: []string{"ssl证书过期", "证书过期", "证书已过期", "ssl证书", "证书失效", "证书错误",
			"tls证书", "证书配置", "证书信任", "证书链", "ssl error", "证书验证失败"},
		Cap: "low",
	},
	{
		Keywords: []string{"缺少安全头", "缺失安全头", "安全响应头", "security header",
			"missing header", "x-frame-options", "csp缺失", "csp 缺失", "hsts缺失", "hsts 缺失",
			"缺少x-content-type-options", "安全头缺失", "headers缺失", "响应头缺失"},
		Cap: "info",
	},
	{
		Keywords: []string{"版本信息泄露", "版本泄露", "版本号泄露", "server版本泄露",
			"版本信息暴露", "banner泄露", "指纹泄露", "favicon指纹", "版本指纹"},
		Cap: "info",
	},
	{
		Keywords: []string{"目录列表", "目录列举", "目录浏览", "目录遍历泄露", "webdav目录",
			"phpinfo", "调试信息泄露", "错误信息泄露", "堆栈信息泄露"},
		Cap: "low",
	},
	{
		Keywords: []string{"默认页面", "测试页面", "欢迎页", "安装页面残留", "示例应用",
			"示例代码", "sample page", "default page"},
		Cap: "info",
	},
	{
		Keywords: []string{"弱口令", "默认口令", "默认账号", "测试账号残留"},
		Cap:      "medium", // 口令类噪音仍可能真实可利用，封顶宽松
	},
}

// ApplyNoiseSeverityCap 对漏洞严重级应用噪音降级：title/type 命中显式清单且
// 当前 severity 高于封顶 → 降级到封顶档位，返回 (是否降级, 降级后的 severity)。
// 已 confirmed 的漏洞不降级（真实证据优先于关键词判断）。
// 只影响展示/排序面，不参与任何拦截/放行决策。
func ApplyNoiseSeverityCap(title, vulnType, severity string, confirmed bool) (bool, string) {
	if confirmed || strings.TrimSpace(severity) == "" {
		return false, severity
	}
	hay := strings.ToLower(strings.TrimSpace(title) + "|" + strings.TrimSpace(vulnType))
	rank := func(s string) int {
		switch s {
		case "critical":
			return 5
		case "high":
			return 4
		case "medium":
			return 3
		case "low":
			return 2
		default:
			return 1 // info / 未知
		}
	}
	curRank := rank(strings.ToLower(strings.TrimSpace(severity)))
	for _, cap := range NoiseCaps {
		capRank := rank(cap.Cap)
		if curRank <= capRank {
			continue // 已低于封顶，无需处理
		}
		for _, kw := range cap.Keywords {
			if strings.Contains(hay, kw) {
				return true, cap.Cap
			}
		}
	}
	return false, severity
}
