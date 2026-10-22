// Package fpscore 指纹评分：把资产命中的指纹（规则名 + 分类 + 技术栈串）
// 折算成 0-100 的可解释分值，用于「按指纹给项目资产排优先级」。
//
// 与 internal/recon/score 的分工：
//   - score 是综合风险（漏洞实证、开放端口、TLS、Web 卫生、业务属性）；
//   - fpscore 只看资产是什么，不掺漏洞和端口结论。
//
// 分值越高，说明资产承载的系统越接近高价值/高暴露面（安防设备、OA/ERP、
// 运维平台、历史上高频出洞的产品），越值得优先投入测试预算。
// 同一资产命中越多指纹，额外指纹只按半量累加：最强指纹决定档位，
// 其余指纹提供佐证，避免「装了一堆普通组件」被抬成高危。
package fpscore

import (
	"sort"
	"strings"
)

// 评分等级。与 risk_score 的 P0-P4 分开命名，避免前端把两套口径混用。
const (
	LevelHigh   = "high"   // >= 70
	LevelMedium = "medium" // >= 40
	LevelLow    = "low"    // 1..39
	LevelNone   = "none"   // 0，没有可用指纹

	// 档位阈值。Level 与 repo 下发的分档计数共用这三个常量，避免两处漂移。
	HighMin   = 70
	MediumMin = 40
	LowMin    = 1

	MaxScore = 100
)

// Source 标明这条指纹来自规则命中还是站点技术栈。
type Source string

const (
	SourceRule Source = "rule"
	SourceTech Source = "tech"
)

// Hit 是一条待评分的指纹观测。
type Hit struct {
	Name     string
	Category string
	Source   Source
}

// Match 是评分明细中的一条命中，前端直接展示「为什么是这个分」。
type Match struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	// CategoryLabel 是分类中文名，未映射时等于 Category。
	CategoryLabel string `json:"category_label"`
	Source        Source `json:"source"`
	Points        int    `json:"points"`
	Reason        string `json:"reason"`
}

// Result 是单资产的指纹评分结果。
type Result struct {
	Score      int      `json:"score"`
	Level      string   `json:"level"`
	Matches    []Match  `json:"matches"`
	Categories []string `json:"categories"`
}

// categoryWeights 是指纹分类的基准分。分类来自 fingerprint_rules.category
// 与 wappalyzer 类技术分类；未列出的分类按 defaultCategoryPoints 计。
var categoryWeights = map[string]int{
	"security-device":       55, // 防火墙 / 上网行为管理 / 堡垒机
	"endpoint-security":     55,
	"pki-ca":                50, // 证书 / CA / 身份基础设施
	"video-surveillance":    45,
	"video-conferencing":    40,
	"gov-enterprise-system": 40,
	"oa":                    40,
	"erp-finance":           40,
	"ops-platform":          35, // 调度 / 发布 / 配置中心
	"mail":                  30,
	"database":              35,
	"devops":                30,
	"monitoring":            30,
	"network":               30,
	"iot":                   40,
	"java-framework":        25,
	"cms":                   15,
	"web-framework":         12,
	"web-server":            10,
	"programming-language":  10,
	"javascript-framework":  10,
	"ui-framework":          8,
	"analytics":             6,
	"font-script":           4,
	// 中性信号：能识别出来，但不代表高价值或高风险，只作为佐证不计分。
	"scripting-library": 0,
	"cloud-storage":     0,
	"cdn":               0,
}

// categoryLabels 是分类的中文展示名。前端直接用，避免两边各维护一份映射。
var categoryLabels = map[string]string{
	"security-device":       "安防设备",
	"endpoint-security":     "终端安全",
	"pki-ca":                "证书/CA",
	"video-surveillance":    "视频监控",
	"video-conferencing":    "视频会议",
	"gov-enterprise-system": "政企系统",
	"oa":                    "OA 办公",
	"erp-finance":           "ERP/财务",
	"ops-platform":          "运维平台",
	"mail":                  "邮件系统",
	"database":              "数据库",
	"devops":                "研发工具",
	"monitoring":            "监控平台",
	"network":               "网络设备",
	"iot":                   "物联网",
	"java-framework":        "Java 框架",
	"cms":                   "CMS",
	"web-framework":         "Web 框架",
	"web-server":            "Web 服务器",
	"programming-language":  "开发语言",
	"javascript-framework":  "前端框架",
	"ui-framework":          "UI 框架",
	"analytics":             "统计分析",
	"font-script":           "字体脚本",
	"cdn":                   "CDN",
	"cloud-storage":         "云存储",
	"scripting-library":     "脚本/组件",
}

// CategoryLabel 返回分类中文名；没有映射时原样返回。
func CategoryLabel(category string) string {
	c := strings.TrimSpace(category)
	if c == "" {
		return ""
	}
	if label, ok := categoryLabels[normalizeCategory(c)]; ok {
		return label
	}
	return c
}

const (
	defaultCategoryPoints = 12 // 有分类但不在字典里
	genericFingerprintPts = 6  // 只知道「识别出了某个组件」，没有分类信息
)

// productWeights 是高风险产品/组件的关键词分。命中即按产品历史暴露面计分，
// 与分类分取较大值。关键词按小写子串匹配，因此 "Apache Tomcat/9.0" 也能命中。
// category 用于反推分类：只有技术栈、没有规则命中时也能参与分类筛选。
var productWeights = []struct {
	keyword  string
	points   int
	category string
}{
	{"kubernetes-dashboard", 60, "Ops-Platform"}, {"jenkins", 55, "DevOps"},
	{"weblogic", 55, "Java-Framework"}, {"nacos", 55, "Ops-Platform"},
	{"dolphinscheduler", 50, "Ops-Platform"}, {"phpmyadmin", 50, "Database"},
	{"shiro", 50, "Java-Framework"}, {"jboss", 50, "Java-Framework"},
	{"struts", 50, "Java-Framework"}, {"thinkphp", 45, "Web-Framework"},
	{"actuator", 45, "DevOps"}, {"druid", 45, "Database"},
	{"rundeck", 45, "Ops-Platform"}, {"xxl-job", 45, "Ops-Platform"},
	{"rancher", 45, "Ops-Platform"}, {"solr", 45, "Database"},
	{"elasticsearch", 40, "Database"}, {"kibana", 40, "Monitoring"},
	{"zabbix", 40, "Monitoring"}, {"gitlab", 40, "DevOps"},
	{"harbor", 40, "DevOps"}, {"confluence", 40, "OA"},
	{"nexus", 40, "DevOps"}, {"airflow", 40, "Ops-Platform"},
	{"superset", 40, "Ops-Platform"}, {"jupyter", 40, "DevOps"},
	{"consul", 40, "Ops-Platform"}, {"apisix", 40, "Network"},
	{"grafana", 35, "Monitoring"}, {"tomcat", 35, "Web-Server"},
	{"minio", 35, "DevOps"}, {"jira", 35, "OA"},
	{"webdav", 35, "Web-Server"}, {"eureka", 35, "Ops-Platform"},
	{"prometheus", 35, "Monitoring"}, {"activemq", 35, "Ops-Platform"},
	{"rocketmq", 35, "Ops-Platform"}, {"skywalking", 35, "Monitoring"},
	{"metabase", 35, "Ops-Platform"}, {"sonarqube", 30, "DevOps"},
	{"sentry", 30, "Monitoring"}, {"traefik", 30, "Network"},
	{"kong", 30, "Network"}, {"spring", 25, "Java-Framework"},
}

// techCategoryWeights 是常见技术栈的分类映射，技术栈命中但不在产品字典时用它
// 补分类。key 是归一化（小写）后的关键词，按子串匹配。
var techCategoryWeights = map[string]string{
	"openresty":  "Web-Server",
	"nginx":      "Web-Server",
	"apache":     "Web-Server",
	"tomcat":     "Web-Server",
	"iis":        "Web-Server",
	"caddy":      "Web-Server",
	"tengine":    "Web-Server",
	"next.js":    "JavaScript-Framework",
	"vue":        "JavaScript-Framework",
	"react":      "JavaScript-Framework",
	"angular":    "JavaScript-Framework",
	"jquery":     "JavaScript-Framework",
	"webpack":    "JavaScript-Framework",
	"cloudflare": "CDN",
	"jsdelivr":   "CDN",
	"echarts":    "UI-Framework",
	"bootstrap":  "UI-Framework",
	"layui":      "UI-Framework",
	"element-ui": "UI-Framework",
	"oracle":     "Database",
	"mysql":      "Database",
	"postgres":   "Database",
	"redis":      "Database",
	"mongodb":    "Database",
	"jsp":        "Programming-Language",
	"java":       "Programming-Language",
	"php":        "Programming-Language",
	"python":     "Programming-Language",
	"go":         "Programming-Language",
	"linkfinder": "Scripting-Library",
	"aws":        "Cloud-Storage",
}

// Compute 计算一个资产的指纹分。hits 中的重名项会去重，规则来源优先于技术栈。
func Compute(hits []Hit) Result {
	matches := make([]Match, 0, len(hits))
	seen := make(map[string]int, len(hits))

	for _, h := range hits {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		category := effectiveCategory(h.Category, name)
		if pos, dup := seen[key]; dup {
			// 同名时规则命中带分类，信息量更大：用规则结果覆盖技术栈结果。
			if matches[pos].Source == SourceTech && h.Source == SourceRule {
				points, reason := scoreHit(name, category)
				matches[pos] = Match{
					Name:          name,
					Category:      category,
					CategoryLabel: CategoryLabel(category),
					Source:        h.Source,
					Points:        points,
					Reason:        reason,
				}
			}
			continue
		}
		seen[key] = len(matches)

		points, reason := scoreHit(name, category)
		matches = append(matches, Match{
			Name:          name,
			Category:      category,
			CategoryLabel: CategoryLabel(category),
			Source:        h.Source,
			Points:        points,
			Reason:        reason,
		})
	}

	// 最强指纹在前，同分按名称稳定排序，分页/展示都不会抖动。
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Points != matches[j].Points {
			return matches[i].Points > matches[j].Points
		}
		return strings.ToLower(matches[i].Name) < strings.ToLower(matches[j].Name)
	})

	// 分类从最终命中集合里收集，避免被规则覆盖掉的技术栈分类残留。
	categories := make([]string, 0, 4)
	seenCategory := make(map[string]struct{}, 4)
	for _, m := range matches {
		addCategory(&categories, seenCategory, m.Category)
	}
	sort.SliceStable(categories, func(i, j int) bool {
		return strings.ToLower(categories[i]) < strings.ToLower(categories[j])
	})

	score := 0
	if len(matches) > 0 {
		score = matches[0].Points
		for _, m := range matches[1:] {
			score += m.Points / 2
		}
		if score > MaxScore {
			score = MaxScore
		}
	}

	if matches == nil {
		matches = []Match{}
	}
	if categories == nil {
		categories = []string{}
	}
	return Result{
		Score:      score,
		Level:      Level(score),
		Matches:    matches,
		Categories: categories,
	}
}

// addCategory 登记分类，供前端按分类筛选。
func addCategory(categories *[]string, seen map[string]struct{}, category string) {
	c := strings.TrimSpace(category)
	if c == "" {
		return
	}
	ck := CategoryKey(c)
	if _, ok := seen[ck]; ok {
		return
	}
	seen[ck] = struct{}{}
	*categories = append(*categories, c)
}

// Level 把分值映射成档位。
func Level(score int) string {
	switch {
	case score >= HighMin:
		return LevelHigh
	case score >= MediumMin:
		return LevelMedium
	case score >= LowMin:
		return LevelLow
	default:
		return LevelNone
	}
}

// LevelLabel 是档位的中文展示名，后端随 facets 下发，前端不重复维护映射。
func LevelLabel(level string) string {
	switch level {
	case LevelHigh:
		return "高危"
	case LevelMedium:
		return "中危"
	case LevelLow:
		return "低危"
	default:
		return "无信号"
	}
}

func scoreHit(name, category string) (int, string) {
	points := 0
	reason := ""
	hasWeight := false

	if cw, ok := categoryWeights[normalizeCategory(category)]; ok {
		points = cw
		hasWeight = true
		reason = "分类「" + CategoryLabel(category) + "」"
	}
	if pw, kw := productPoints(name); pw > points {
		points = pw
		hasWeight = true
		reason = "高风险产品「" + kw + "」"
	}
	if !hasWeight {
		if strings.TrimSpace(category) != "" {
			points = defaultCategoryPoints
			reason = "分类「" + CategoryLabel(category) + "」"
		} else {
			points = genericFingerprintPts
			reason = "通用组件指纹"
		}
	}
	return points, reason
}

// genericCategoryTokens 是上游同步时把来源字段写进分类的占位值，
// 它们不是产品分类，不能拿来给资产分档。
var genericCategoryTokens = map[string]bool{
	"dddd": true, "wappalyzergo": true, "webanalyze": true,
	"seed": true, "custom": true, "upstream": true,
}

// effectiveCategory 优先用规则给的分类；来源占位值或空值时按产品名反推。
func effectiveCategory(explicit, name string) string {
	c := strings.TrimSpace(explicit)
	if c != "" && !genericCategoryTokens[strings.ToLower(c)] {
		return c
	}
	return CategoryOf(name)
}

// CategoryOf 在产品字典命中时反推分类，让只有技术栈（没有规则命中）的资产
// 也能参与分类筛选与统计。规则命中带分类时一律以规则为准。
func CategoryOf(name string) string {
	lower := strings.ToLower(name)
	bestPts, category := 0, ""
	for _, p := range productWeights {
		if p.points > bestPts && strings.Contains(lower, p.keyword) {
			bestPts, category = p.points, p.category
		}
	}
	if category != "" {
		return category
	}
	if _, ok := techCategoryWeights[strings.TrimSpace(lower)]; ok {
		return techCategoryWeights[strings.TrimSpace(lower)]
	}
	// 字典遍历顺序随机，取最短关键词保证结果稳定。
	kw, cat := "", ""
	for k, c := range techCategoryWeights {
		if !strings.Contains(lower, k) {
			continue
		}
		if kw == "" || len(k) < len(kw) || (len(k) == len(kw) && k < kw) {
			kw, cat = k, c
		}
	}
	return cat
}

func productPoints(name string) (int, string) {
	lower := strings.ToLower(name)
	best, keyword := 0, ""
	for _, p := range productWeights {
		if strings.Contains(lower, p.keyword) && p.points > best {
			best, keyword = p.points, p.keyword
		}
	}
	return best, keyword
}

// CategoryKey 把 "Video Surveillance" / "video_surveillance" 统一成
// "video-surveillance"，供评分、去重与筛选共用一套口径。
func CategoryKey(category string) string {
	return normalizeCategory(category)
}

func normalizeCategory(category string) string {
	c := strings.ToLower(strings.TrimSpace(category))
	c = strings.ReplaceAll(c, "_", "-")
	c = strings.ReplaceAll(c, " ", "-")
	for strings.Contains(c, "--") {
		c = strings.ReplaceAll(c, "--", "-")
	}
	return strings.Trim(c, "-")
}
