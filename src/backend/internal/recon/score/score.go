// Package score 资产脆弱性优先级评分：从暴露面、服务/指纹、漏洞实证、TLS、
// Web 卫生、业务属性六个维度加权，输出 0-100 分 + P0-P4 优先级 + 因子明细
// （明细落 asset_risk_factors，前端可解释展示）。
//
// 设计原则：只减不加信噪比——泛解析命中减半、无 HTTP 结论的维度不打分，
// 每个加分点都要求有观测证据（端口开放/指纹命中/证书状态/响应头）。
package score

import (
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/internal/recon/successsignal"
)

// Input 评分输入（全部来自观测，不引入任何外部情报依赖）。
type Input struct {
	OpenPorts    []int  // TCP 开放端口
	EdgeType     string // cdn/waf/cloud/local（cdnmatch 结论；空=未解析）
	IsWildcard   bool   // 泛解析命中
	Server       string // Server 响应头 / 指纹产品串
	Title        string
	Fingerprints []string
	HTTPStatus   int
	HTTPSeen     bool // 是否完成 HTTP 探测（false 则 web 卫生维度不计）

	// 漏洞实证：关联资产的漏洞严重度（0=无, 1=info .. 5=critical）
	VulnSeverity int
	VulnCount    int

	// 业务属性
	Criticality string // 核心/重要/一般（用户在资产库维护）
	HasOwner    bool   // 是否有责任人/部门归属（false = 影子资产）

	// TLS（由 pipeline 从证书文本解析）
	CertExpired    bool
	CertSelfSigned bool
	CertYearsValid bool // 有效期 > 3 年（长证书纪律松弛）

	// Web 卫生
	MissingSecurityHeaders []string // HSTS/CSP/X-Content-Type-Options 等
	DirectoryListing       bool     // 目录列表开启
	DefaultPage            bool     // 默认/示例页特征

	// 蜜罐甄别（recon/honeypot 结论）："" / "suspect" / "likely"。
	// likely 强制压到 p4（蜜罐资产不值得消耗测试预算），suspect 减 20 分。
	Honeypot string

	// 高产路径先验（对标 AutoHunter #2）：资产上观测到的 URL path
	// （工具结果/爬虫面），命中「历史出洞多的路径族」时叠加先验分（上限 10）。
	Paths []string
}

type factorOut struct {
	Factor string
	Points int
	Detail string
}

// Compute 返回 (0-100 分, P0-P4 级别, 因子明细)。
func Compute(in Input) (int, string, []factorOut) {
	factors := make([]factorOut, 0, 8)
	total := 0

	// ── 1. 漏洞实证（25）──
	vulnPts := 0
	vulnDetail := "无已关联漏洞"
	switch in.VulnSeverity {
	case 5:
		vulnPts = 25
		vulnDetail = fmt.Sprintf("存在 critical 漏洞（共 %d 个）", in.VulnCount)
	case 4:
		vulnPts = 20
		vulnDetail = fmt.Sprintf("存在 high 漏洞（共 %d 个）", in.VulnCount)
	case 3:
		vulnPts = 12
		vulnDetail = fmt.Sprintf("存在 medium 漏洞（共 %d 个）", in.VulnCount)
	case 2:
		vulnPts = 6
		vulnDetail = fmt.Sprintf("存在 low 漏洞（共 %d 个）", in.VulnCount)
	case 1:
		vulnPts = 2
		vulnDetail = fmt.Sprintf("仅 info 级漏洞（共 %d 个）", in.VulnCount)
	}
	if vulnPts > 0 {
		total += vulnPts
		factors = append(factors, factorOut{"vuln", vulnPts, vulnDetail})
	}

	// ── 2. 暴露面（25）──
	exposure := 0
	var exposureNotes []string
	if risky, note := riskyPortPoints(in.OpenPorts); risky > 0 {
		exposure += risky
		exposureNotes = append(exposureNotes, note)
	}
	if in.EdgeType == "" || in.EdgeType == "local" {
		if len(in.OpenPorts) > 0 {
			exposure += 5 // 源站直连公网（无 CDN 遮蔽）
			exposureNotes = append(exposureNotes, "公网直连（无 CDN/WAF 遮蔽）")
		}
	}
	if len(in.OpenPorts) > 10 {
		exposure += 3
		exposureNotes = append(exposureNotes, fmt.Sprintf("开放端口较多（%d 个）", len(in.OpenPorts)))
	}
	if exposure > 25 {
		exposure = 25
	}
	if exposure > 0 {
		total += exposure
		factors = append(factors, factorOut{"exposure", exposure, strings.Join(exposureNotes, "；")})
	}

	// ── 3. 服务/指纹（20）──
	servicePts, serviceHits := serviceRiskPoints(in)
	if servicePts > 0 {
		total += servicePts
		factors = append(factors, factorOut{"service", servicePts, strings.Join(serviceHits, "、")})
	}

	// ── 3.5 管理后台/控制台语义（12）──
	// 与 service 产品命中正交:命中产品说明"是什么",控制台语义说明"这是后台入口"。
	// 仅认观测证据(标题/指纹文本),不凭 URL 猜测。多标记叠加取档,上限 12。
	if consolePts, consoleHits := adminConsolePoints(in); consolePts > 0 {
		total += consolePts
		factors = append(factors, factorOut{"admin_console", consolePts, strings.Join(consoleHits, "、")})
	}

	// ── 3.7 高产路径先验（10）──
	// 观测到的路径命中「历史出洞多的路径族」（后台/上传/API 文档/调试端点等）
	// 时叠加先验分；与 3.5 的差别：3.5 认标题/指纹说「这是后台」，这里认 URL
	// 路径说「这个入口历史高产」。表可配置（configs/success-signals.yaml）。
	if priorPts, priorFams := successsignal.Match(in.Paths); priorPts > 0 {
		total += priorPts
		factors = append(factors, factorOut{"success_signal", priorPts, "高产路径先验：" + strings.Join(priorFams, "、")})
	}

	// ── 4. TLS（10）──
	tlsPts := 0
	var tlsNotes []string
	if in.CertExpired {
		tlsPts += 6
		tlsNotes = append(tlsNotes, "证书已过期")
	}
	if in.CertSelfSigned {
		tlsPts += 4
		tlsNotes = append(tlsNotes, "自签名证书")
	}
	if in.CertYearsValid {
		tlsPts += 3
		tlsNotes = append(tlsNotes, "证书有效期超过 3 年")
	}
	if tlsPts > 10 {
		tlsPts = 10
	}
	if tlsPts > 0 {
		total += tlsPts
		factors = append(factors, factorOut{"tls", tlsPts, strings.Join(tlsNotes, "；")})
	}

	// ── 5. Web 卫生（10）──
	if in.HTTPSeen {
		hygiene := 0
		var hygieneNotes []string
		if in.DirectoryListing {
			hygiene += 8
			hygieneNotes = append(hygieneNotes, "目录列表开启")
		}
		if len(in.MissingSecurityHeaders) > 0 {
			pts := len(in.MissingSecurityHeaders) * 2
			if pts > 4 {
				pts = 4
			}
			hygiene += pts
			hygieneNotes = append(hygieneNotes, "缺少安全头 "+strings.Join(in.MissingSecurityHeaders, "/"))
		}
		if in.DefaultPage {
			hygiene += 2
			hygieneNotes = append(hygieneNotes, "默认/示例页特征")
		}
		if hygiene > 10 {
			hygiene = 10
		}
		if hygiene > 0 {
			total += hygiene
			factors = append(factors, factorOut{"hygiene", hygiene, strings.Join(hygieneNotes, "；")})
		}
	}

	// ── 6. 业务属性（10）──
	// 守卫：只有存在观测证据（HTTP 探活/端口/漏洞/关键性）时才计业务因子，
	// 纯空输入不因"影子资产"凭空得分。
	hasObservation := in.HTTPSeen || len(in.OpenPorts) > 0 || in.VulnCount > 0 ||
		in.CertExpired || in.CertSelfSigned || in.Criticality != ""
	if hasObservation {
		bizPts := 0
		var bizNotes []string
		// 资产库落库值固定为英文（validateAsset 只允许 critical/high/medium/low），
		// 中文为设计初稿口径，兼容保留。
		switch in.Criticality {
		case "核心", "critical":
			bizPts += 7
			bizNotes = append(bizNotes, "核心业务资产")
		case "重要", "high":
			bizPts += 4
			bizNotes = append(bizNotes, "重要业务资产")
		case "一般", "medium":
			bizPts += 2
		}
		if !in.HasOwner {
			bizPts += 3
			bizNotes = append(bizNotes, "无归属责任人（影子资产特征）")
		}
		if bizPts > 10 {
			bizPts = 10
		}
		if bizPts > 0 {
			total += bizPts
			factors = append(factors, factorOut{"business", bizPts, strings.Join(bizNotes, "；")})
		}
	}

	// ── 调节项：泛解析命中减半（噪声嫌疑，见 srcradar §八-1）──
	if in.IsWildcard && total > 0 {
		half := total / 2
		factors = append(factors, factorOut{"wildcard", -half, "泛解析命中：结论存疑，评分减半"})
		total -= half
	}

	// ── 调节项：蜜罐甄别降级（likely 强制 p4；资产不删除，人工可复核 tag）──
	level := Level(total)
	switch in.Honeypot {
	case "likely":
		total -= 40
		factors = append(factors, factorOut{"honeypot", -40, "蜜罐甄别 likely：疑似蜜罐（诱捕环境），优先级强制压到 p4，建议与授权方核实后再处置"})
		level = "p4"
	case "suspect":
		total -= 20
		factors = append(factors, factorOut{"honeypot", -20, "蜜罐甄别 suspect：存在蜜罐特征（端口/协议/暴露面密度异常）"})
	}

	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}
	return total, level, factors
}

// Level 分数 → P0-P4。
func Level(score int) string {
	switch {
	case score >= 80:
		return "p0"
	case score >= 60:
		return "p1"
	case score >= 40:
		return "p2"
	case score >= 15:
		return "p3"
	default:
		return "p4"
	}
}

// riskyPortDict 高危端口字典（包级，避免每次评分重建）。
var riskyPortDict = map[int]struct {
	pts  int
	name string
}{
	23:    {20, "Telnet"},
	3389:  {18, "RDP"},
	6379:  {18, "Redis"},
	9200:  {18, "Elasticsearch"},
	2375:  {20, "Docker API"},
	27017: {16, "MongoDB"},
	445:   {14, "SMB"},
	1433:  {14, "MSSQL"},
	5900:  {14, "VNC"},
	11211: {14, "Memcached"},
	3306:  {12, "MySQL"},
	5432:  {12, "PostgreSQL"},
	7001:  {12, "WebLogic"},
	8848:  {12, "Nacos"},
	21:    {10, "FTP"},
	161:   {10, "SNMP"},
	6443:  {8, "K8s API"},
	5601:  {8, "Kibana"},
}

// riskyPortPoints 高危端口字典：返回（分数, 命中描述）。取最高一个端口计分，
// 其余命中并入描述（多高危端口叠加意义有限，避免重复计权）。
// adminConsoleDict 控制台语义标记 → 分值(标题/指纹文本匹配)。
// 弱标记(admin/login)仅在强标记(后台/控制台类)共存时计分,防营销页误报。
var adminConsoleDict = []struct {
	keyword string
	pts     int
	strong  bool
}{
	{"管理后台", 8, true}, {"后台管理", 8, true}, {"管理系统", 6, true},
	{"控制台", 6, true}, {"console", 4, true}, {"dashboard", 4, true},
	{"运维平台", 6, true}, {"admin", 3, false}, {"登录", 2, false}, {"login", 2, false},
}

// adminConsolePoints 管理后台/控制台语义因子:强标记直接计,弱标记仅在
// 存在强标记时叠加;合计上限 12。
func adminConsolePoints(in Input) (int, []string) {
	texts := []string{strings.ToLower(in.Title)}
	for _, fp := range in.Fingerprints {
		texts = append(texts, strings.ToLower(fp))
	}
	joined := strings.Join(texts, "|")
	if joined == "|" {
		return 0, nil
	}
	pts := 0
	hasStrong := false
	var hits []string
	for _, m := range adminConsoleDict {
		if !strings.Contains(joined, m.keyword) {
			continue
		}
		if m.strong {
			if !hasStrong {
				hasStrong = true
			}
			pts += m.pts
			hits = append(hits, m.keyword)
		} else if hasStrong {
			pts += m.pts
			hits = append(hits, m.keyword)
		}
	}
	if !hasStrong || pts == 0 {
		return 0, nil
	}
	if pts > 12 {
		pts = 12
	}
	return pts, hits
}

func riskyPortPoints(ports []int) (int, string) {
	if len(ports) == 0 {
		return 0, ""
	}
	var hits []string
	maxPts := 0
	for _, p := range ports {
		if entry, ok := riskyPortDict[p]; ok {
			hits = append(hits, fmt.Sprintf("%s(%d)", entry.name, p))
			if entry.pts > maxPts {
				maxPts = entry.pts
			}
		}
	}
	if maxPts == 0 {
		return 0, ""
	}
	return maxPts, "高危端口暴露 " + strings.Join(hits, "、")
}

// riskyProductDict 高风险产品关键词 → 风险分（代表该产品线历史上高频出现可利用面）。
var riskyProductDict = []struct {
	keyword string
	pts     int
}{
	{"jenkins", 16}, {"weblogic", 16}, {"nacos", 14}, {"struts", 14}, {"thinkphp", 14},
	{"phpmyadmin", 14}, {"actuator", 14}, {"shiro", 12}, {"jboss", 12}, {"druid", 12},
	{"elasticsearch", 10}, {"solr", 12}, {"kibana", 10}, {"grafana", 10}, {"zabbix", 10},
	{"gitlab", 10}, {"harbor", 10}, {"minio", 8}, {"tomcat", 8}, {"spring", 8},
	{"confluence", 12}, {"jira", 10}, {"webdav", 10}, {"rundeck", 12}, {"nexus", 10},
	// 管理后台/调度/数据平台/容器平台(实测高频未授权面:小鹏项目 dolphinscheduler/
	// apisix-dashboard/prometheus 曾被压到 P4,2026-09-11 补齐)
	{"dolphinscheduler", 14}, {"apisix", 12}, {"kubernetes-dashboard", 14}, {"rancher", 12},
	{"xxl-job", 12}, {"airflow", 10}, {"superset", 10}, {"eureka", 10},
	{"prometheus", 8}, {"consul", 10}, {"activemq", 8}, {"rocketmq", 8}, {"skywalking", 10},
	{"sonarqube", 8}, {"sentry", 8}, {"metabase", 8}, {"jupyter", 10}, {"traefik", 8}, {"kong", 8},
}

// serviceRiskPoints 高风险产品关键词（fingerprint 命中/Server 头/标题）。
// 取最高一档 + 多产品附加，上限 20。
func serviceRiskPoints(in Input) (int, []string) {
	texts := []string{strings.ToLower(in.Server), strings.ToLower(in.Title)}
	for _, fp := range in.Fingerprints {
		texts = append(texts, strings.ToLower(fp))
	}
	joined := strings.Join(texts, "|")
	if joined == "|" {
		return 0, nil
	}
	maxPts := 0
	distinct := 0
	var hits []string
	for _, product := range riskyProductDict {
		if strings.Contains(joined, product.keyword) {
			distinct++
			hits = append(hits, product.keyword)
			if product.pts > maxPts {
				maxPts = product.pts
			}
		}
	}
	if maxPts == 0 {
		return 0, nil
	}
	if distinct > 1 {
		maxPts += 4 // 多个高风险产品共存
	}
	if maxPts > 20 {
		maxPts = 20
	}
	return maxPts, hits
}
