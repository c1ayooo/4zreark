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
	ErrorPage              bool     // 错误/调试页（框架、堆栈、SQL 报错等）

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

	// ── 3.6 错误/调试页（8）──
	// 错误页本身是弱证据，但它暴露框架/堆栈/SQL 方言，是「可能有洞」的旁证。
	if in.ErrorPage {
		total += 8
		factors = append(factors, factorOut{"error_page", 8, "错误/调试页暴露框架或堆栈信息"})
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
	case score >= 30:
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
	2375:  {20, "Docker API"},
	2376:  {20, "Docker API (TLS)"},
	3389:  {18, "RDP"},
	6379:  {18, "Redis"},
	9200:  {18, "Elasticsearch"},
	6443:  {18, "K8s API"},
	10250: {18, "Kubelet API"},
	27017: {16, "MongoDB"},
	15672: {16, "RabbitMQ 管理台"},
	2379:  {16, "etcd"},
	2380:  {16, "etcd peer"},
	50070: {16, "HDFS NameNode"},
	9000:  {16, "MinIO"},
	9001:  {16, "MinIO Console"},
	7001:  {16, "WebLogic"},
	7002:  {16, "WebLogic (SSL)"},
	445:   {14, "SMB"},
	1433:  {14, "MSSQL"},
	5900:  {14, "VNC"},
	11211: {14, "Memcached"},
	2181:  {14, "ZooKeeper"},
	2049:  {14, "NFS"},
	9300:  {14, "Elasticsearch transport"},
	10000: {14, "Webmin"},
	8088:  {14, "YARN ResourceManager"},
	16010: {14, "HBase Master"},
	9042:  {14, "Cassandra"},
	8848:  {14, "Nacos"},
	3306:  {12, "MySQL"},
	5432:  {12, "PostgreSQL"},
	1521:  {12, "Oracle"},
	9092:  {12, "Kafka"},
	8500:  {12, "Consul"},
	8086:  {12, "InfluxDB"},
	5601:  {12, "Kibana"},
	21:    {10, "FTP"},
	161:   {10, "SNMP"},
	139:   {10, "NetBIOS"},
	873:   {10, "rsync"},
	5000:  {10, "Docker Registry"},
	8888:  {10, "Jupyter"},
	389:   {8, "LDAP"},
	636:   {8, "LDAPS"},
	111:   {8, "rpcbind"},
	19888: {8, "Hadoop JobHistory"},
	9090:  {10, "Prometheus"},
	3000:  {10, "Grafana"},
	5672:  {8, "RabbitMQ"},
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

// riskyProductDict 高风险产品/组件关键词 → 风险分。
//
// 分组口径：
//   - S 40：历史 RCE / 反序列化 / 未授权执行（WebLogic/Struts/Shiro/Fastjson/
//     Log4j/Jenkins/HZERO/Actuator/K8s Dashboard 等）
//   - A 25-35：常见未授权管理面/数据平台/对象存储（Nacos/Eureka/Druid/
//     Jupyter/Airflow/XXL-JOB/MinIO/S3 桶/phpMyAdmin 等）
//   - B 8-20：通用组件/CMS/调试页/敏感路径（Tomcat/JSP/Swagger/.git 等）
//
// family 用于去重：同一产品的多个关键词只计一次（如 spring/spring boot）。
// keyword 长度 <=3 时按 token 精确匹配，避免 s3 命中 s3cr3t、cos 命中 cost。
var riskyProductDict = []struct {
	keyword string
	family  string
	pts     int
}{
	// ── S：历史 RCE / 反序列化 / 未授权执行 ──
	{"actuator", "actuator", 40},
	{"hzero", "", 40},
	{"weblogic", "", 40},
	{"struts", "", 40},
	{"shiro", "", 40},
	{"fastjson", "", 40},
	{"log4j", "", 40},
	{"jenkins", "jenkins", 40},
	{"hudson", "jenkins", 35},
	{"kubernetes-dashboard", "k8s-dashboard", 40},
	{"jboss", "jboss", 35},
	{"wildfly", "jboss", 35},
	{"confluence", "", 35},
	{"gitlab", "", 35},
	{"harbor", "", 35},
	{"thinkphp", "", 35},
	{"dolphinscheduler", "", 35},
	{"citrix", "citrix", 35},
	{"netscaler", "citrix", 35},
	{"solr", "", 30},
	{"ofbiz", "", 30},
	{"rundeck", "", 30},
	{"webmin", "", 30},
	{"vcenter", "", 30},
	{"exchange", "", 30},
	{"fortinet", "fortinet", 30},
	{"fortigate", "fortinet", 30},
	{"pulse secure", "", 30},
	{"pan-os", "", 30},
	{"sonicwall", "", 30},
	{"apisix", "apisix", 30},
	{"h2-console", "h2", 25},
	{"jmx-console", "jmx", 25},
	{"jmx", "jmx", 20},

	// ── A：常见未授权管理面 / 数据平台 / 对象存储 ──
	{"spring boot", "spring", 35},
	{"springboot", "spring", 35},
	{"spring cloud", "spring", 35},
	{"spring", "spring", 30},
	{"nacos", "", 30},
	{"eureka", "", 25},
	{"consul", "", 25},
	{"druid", "", 25},
	{"kubernetes", "k8s", 30},
	{"k8s", "k8s", 30},
	{"rancher", "", 30},
	{"portainer", "", 30},
	{"argocd", "", 30},
	{"kubesphere", "", 25},
	{"openshift", "", 25},
	{"nexus", "", 30},
	{"minio", "object-storage", 30},
	{"aws-bucket", "object-storage", 30},
	{"aws bucket", "object-storage", 30},
	{"bucket", "object-storage", 30},
	{"s3", "object-storage", 30},
	{"oss", "object-storage", 30},
	{"cos", "object-storage", 30},
	{"storage", "object-storage", 20},
	{"phpmyadmin", "", 30},
	{"adminer", "", 30},
	{"myadmin", "phpmyadmin", 25},
	{"jupyter", "", 30},
	{"airflow", "", 30},
	{"xxl-job", "xxl-job", 30},
	{"xxljob", "xxl-job", 30},
	{"superset", "", 30},
	{"metabase", "", 25},
	{"kibana", "", 25},
	{"elasticsearch", "", 25},
	{"rabbitmq", "", 20},
	{"activemq", "", 25},
	{"rocketmq", "", 25},
	{"zookeeper", "", 25},
	{"kafka", "", 20},
	{"hdfs", "", 30},
	{"hadoop yarn", "", 30},
	{"resourcemanager", "", 30},
	{"apache hive", "", 20},
	{"hive server", "", 20},
	{"hbase", "", 25},
	{"spark", "", 25},
	{"flink", "", 30},
	{"hue", "", 30},
	{"zeppelin", "", 30},
	{"livy", "", 25},
	{"sonarqube", "", 20},
	{"sentry", "", 20},
	{"grafana", "", 20},
	{"prometheus", "", 15},
	{"zabbix", "", 20},
	{"skywalking", "", 20},
	{"apollo", "", 25},
	{"seata", "", 20},
	{"sentinel", "", 20},
	{"dubbo", "", 25},
	{"ruoyi", "", 30},
	{"jeecg", "", 30},
	{"magic-api", "magic-api", 30},
	{"jimureport", "", 25},
	{"dataease", "", 25},
	{"erupt", "", 25},
	{"shenyu", "", 25},
	{"wordpress", "", 20},
	{"drupal", "", 20},
	{"joomla", "", 20},
	{"discuz", "", 25},
	{"dedecms", "", 25},
	{"phpcms", "", 25},
	{"typecho", "", 15},
	{"eyoucms", "", 20},
	{"laravel", "", 15},
	{"django", "", 20},
	{"flask", "", 20},
	{"werkzeug", "", 20},
	{"rails", "", 15},
	{"tomcat", "", 15},
	{"jsp", "", 8},
	{"swagger", "", 15},
	{"knife4j", "", 15},
	{"openapi", "", 15},
	{"graphql", "", 15},
	{"redoc", "", 10},
	{"phpinfo", "", 25},
	{".git", "", 25},
	{".svn", "", 20},
	{".env", "", 25},
	{"backup", "", 15},
	{"dump", "", 15},
	{"webdav", "", 20},
	{"ftp", "", 10},
	{"smb", "", 15},
	{"nfs", "", 15},
	{"ldap", "", 15},
	{"rsync", "", 10},
	{"telnet", "", 15},
	{"rdp", "", 15},
	{"vnc", "", 15},
	{"snmp", "", 10},
	{"iis", "", 10},
	{"asp.net", "", 15},
	{"cpanel", "", 20},
	{"plesk", "", 20},
	{"宝塔", "", 25},
	{"bt panel", "", 25},
	{"redis", "", 15},
	{"mongodb", "", 15},
	{"memcached", "", 15},
	{"mysql", "", 10},
	{"postgres", "", 10},
	{"oracle", "", 10},
	{"mssql", "", 10},
	{"cassandra", "", 15},
	{"couchdb", "", 20},
	{"influxdb", "", 20},
	{"netdata", "", 15},
	{"nagios", "", 15},
	{"cacti", "", 20},
	{"victoriametrics", "", 15},
	{"zipkin", "", 15},
	{"jaeger", "", 15},
	{"gitea", "", 25},
	{"gogs", "", 25},
	{"bitbucket", "", 25},
	{"teamcity", "", 25},
	{"bamboo", "", 20},
	{"drone", "", 20},
	{"spinnaker", "", 25},
	{"awx", "", 25},
	{"kong", "", 20},
	{"traefik", "", 15},
	{"envoy", "", 15},
	{"caddy", "", 10},
	{"logstash", "", 15},
	{"jira", "", 30},
}

// serviceRiskPoints 高风险产品关键词（fingerprint 命中/Server 头/标题）。
// 取最高一档 + 多产品附加（每个额外产品 +4，上限 40）。
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
	seen := make(map[string]bool, 8)
	for _, product := range riskyProductDict {
		if !keywordHit(joined, product.keyword) {
			continue
		}
		fam := product.family
		if fam == "" {
			fam = product.keyword
		}
		if seen[fam] {
			continue
		}
		seen[fam] = true
		distinct++
		hits = append(hits, product.keyword)
		if product.pts > maxPts {
			maxPts = product.pts
		}
	}
	if maxPts == 0 {
		return 0, nil
	}
	if distinct > 1 {
		maxPts += 4 * (distinct - 1)
	}
	if maxPts > 40 {
		maxPts = 40
	}
	return maxPts, hits
}

// keywordHit 对短关键词按 token 精确匹配（s3/cos/oss/k8s 等），
// 长关键词按子串匹配。避免 "s3" 命中 "s3cr3t"、"cos" 命中 "cost"。
func keywordHit(joined, keyword string) bool {
	joined = strings.ToLower(joined)
	keyword = strings.ToLower(keyword)
	if keyword == "" {
		return false
	}
	if len(keyword) > 3 {
		return strings.Contains(joined, keyword)
	}
	for _, token := range strings.FieldsFunc(joined, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_')
	}) {
		if token == keyword {
			return true
		}
	}
	return false
}
