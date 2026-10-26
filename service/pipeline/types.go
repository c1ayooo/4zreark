package pipeline

import "time"

// 流水线数据类型定义
// 定义模块间传递的数据结构，实现流式处理

// SubdomainResult 子域名扫描结果
// 由子域名扫描模块输出，传递给子域名安全检测模块
type SubdomainResult struct {
	Host       string   `json:"host"`        // 子域名
	Domain     string   `json:"domain"`      // 根域名
	IPs        []string `json:"ips"`         // 解析的IP地址列表
	CNAMEs     []string `json:"cnames"`      // CNAME记录
	Type       string   `json:"type"`        // 记录类型: A, AAAA, CNAME
	Source     string   `json:"source"`      // 来源: fofa, hunter, brute, httpx
	TaskID     string   `json:"task_id"`     // 任务ID
	TaskName   string   `json:"task_name"`   // 任务名称
	RootDomain string   `json:"root_domain"` // 根域名
	// HTTP 探测结果
	Title        string   `json:"title"`        // 页面标题
	StatusCode   int      `json:"status_code"`  // HTTP 状态码
	WebServer    string   `json:"web_server"`   // Web 服务器
	Technologies []string `json:"technologies"` // 技术栈/指纹
	CDN          bool     `json:"cdn"`          // 是否为 CDN
	CDNName      string   `json:"cdn_name"`     // CDN 名称
	URL          string   `json:"url"`          // 完整 URL
}

// DomainResolve 域名解析结果
// 由子域名安全检测模块输出，传递给端口扫描预处理模块
type DomainResolve struct {
	Domain string   `json:"domain"` // 域名
	IP     []string `json:"ip"`     // 解析的IP
}

// DomainSkip 端口扫描预处理结果
// 由端口扫描预处理模块输出，传递给端口扫描模块
// 包含CDN检测结果，决定是否跳过该域名的端口扫描
type DomainSkip struct {
	Domain string   `json:"domain"` // 域名
	IP     []string `json:"ip"`     // 解析的IP
	Skip   bool     `json:"skip"`   // 是否跳过端口扫描（如CDN）
	IsCDN  bool     `json:"is_cdn"` // 是否为CDN
	CDN    string   `json:"cdn"`    // CDN提供商名称
	CIDR   bool     `json:"cidr"`   // 是否为CIDR格式
}

// PortAlive 端口存活结果
// 由端口扫描模块输出，传递给端口指纹识别模块
type PortAlive struct {
	Host    string `json:"host"`    // 域名或IP
	IP      string `json:"ip"`      // IP地址
	Port    string `json:"port"`    // 端口号
	Service string `json:"service"` // 初步识别的服务
}

// AssetOther 非HTTP资产
// 由端口指纹识别模块输出
type AssetOther struct {
	Host    string `json:"host"`    // 域名
	IP      string `json:"ip"`      // IP地址
	Port    string `json:"port"`    // 端口
	Service string `json:"service"` // 服务类型
	Type    string `json:"type"`    // 资产类型: http, other
	Banner  string `json:"banner"`  // Banner信息
	Version string `json:"version"` // 版本信息
}

// AssetHttp HTTP资产
// 由资产测绘模块输出，传递给URL扫描和漏洞扫描模块
type AssetHttp struct {
	Host         string   `json:"host"`         // 域名
	IP           string   `json:"ip"`           // IP地址
	Port         string   `json:"port"`         // 端口
	URL          string   `json:"url"`          // 完整URL
	Title        string   `json:"title"`        // 页面标题
	StatusCode   int      `json:"status_code"`  // 状态码
	Server       string   `json:"server"`       // Web服务器
	ContentType  string   `json:"content_type"` // 内容类型
	BodyHash     string   `json:"body_hash,omitempty"` // 响应体 MD5：页面模板/版本指纹（fpmine body 聚类用）
	CertOrg      string   `json:"cert_org,omitempty"`   // TLS 证书 Organization（资产归属）
	CertNotAfter time.Time `json:"cert_not_after,omitempty"` // TLS 证书到期时间（证书到期提醒用）
	CookieNames  []string `json:"cookie_names,omitempty"` // Set-Cookie 名集合（框架/网关特征）
	JSFrameworks []string `json:"js_frameworks,omitempty"` // JS 框架@版本（页面版本指纹）
	APIHosts     []string `json:"api_hosts,omitempty"`   // JS 引用的域名（跨域 API 归属线索）
	Technologies []string `json:"technologies"` // 识别的技术栈
	Fingerprints []string `json:"fingerprints"` // 指纹信息
	// 图标：扫描阶段顺手抓到就随资产一起入库，前端按 sha256 取图。
	IconSHA256      string `json:"icon_sha256,omitempty"`
	IconMMH3        int64  `json:"icon_mmh3,omitempty"`
	IconContentType string `json:"icon_content_type,omitempty"`
	IconData        []byte `json:"-"`
}

// UrlResult URL扫描结果
// 由URL扫描模块输出
type UrlResult struct {
	Input       string `json:"input"`        // 输入URL
	Output      string `json:"output"`       // 发现的URL
	Source      string `json:"source"`       // 来源: katana, wayback, rad
	Method      string `json:"method"`       // HTTP方法
	StatusCode  int    `json:"status_code"`  // HTTP状态码
	ContentType string `json:"content_type"` // 内容类型
	Length      int64  `json:"length"`       // 响应长度
	// 发现位置：页面里的哪个标签/属性、来自哪个页面。
	// jsluice-fetch / xhr 这类来源是接口判定最可靠的信号。
	Tag       string `json:"tag,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	Referrer  string `json:"referrer,omitempty"`
	ResultId  string `json:"result_id"` // 结果ID (用于去重)
}

// SensitiveInfoResult 敏感信息检测结果
type SensitiveInfoResult struct {
	Target     string   `json:"target"`     // 目标URL
	URL        string   `json:"url"`        // 发现位置
	Type       string   `json:"type"`       // 敏感信息类型: api_key, password, token, email, phone, id_card, etc
	Pattern    string   `json:"pattern"`    // 匹配的模式名称
	Matches    []string `json:"matches"`    // 匹配到的内容
	Location   string   `json:"location"`   // 位置: body, header, js, url
	Severity   string   `json:"severity"`   // 严重程度: critical, high, medium, low, info
	Confidence int      `json:"confidence"` // 置信度 0-100
	Source     string   `json:"source"`     // 来源
}

// SubTakeResult 子域名接管检测结果 (旧版，保留兼容)
type SubTakeResult struct {
	Input    string `json:"input"`    // 输入子域名
	Value    string `json:"value"`    // 接管类型
	Cname    string `json:"cname"`    // CNAME记录
	Response string `json:"response"` // 响应特征
	TaskName string `json:"task_name"`
}

// TakeoverResult 子域名接管检测结果
type TakeoverResult struct {
	Domain       string   `json:"domain"`       // 子域名
	CNAME        string   `json:"cname"`        // CNAME记录
	Service      string   `json:"service"`      // 可接管的云服务
	Vulnerable   bool     `json:"vulnerable"`   // 是否存在接管风险
	Fingerprints []string `json:"fingerprints"` // 匹配的指纹
	Reason       string   `json:"reason"`       // 判定原因
}

// VulnResult 漏洞扫描结果
type VulnResult struct {
	Target      string            `json:"target"`
	VulnID      string            `json:"vuln_id"`
	Name        string            `json:"name"`
	Severity    string            `json:"severity"` // critical, high, medium, low, info
	Type        string            `json:"type"`
	Description string            `json:"description,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	POC         string            `json:"poc,omitempty"`
	Detail      string            `json:"detail,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Reference   []string          `json:"reference,omitempty"`
	MatchedAt   string            `json:"matched_at,omitempty"`
	ExtractInfo map[string]string `json:"extract_info,omitempty"`
	Source      string            `json:"source"` // nuclei, custom
	Timestamp   time.Time         `json:"timestamp"`
}

// PipelineStats 流水线统计信息
type PipelineStats struct {
	SubdomainsFound int `json:"subdomains_found"`
	PortsFound      int `json:"ports_found"`
	URLsFound       int `json:"urls_found"`
	VulnsFound      int `json:"vulns_found"`
	TotalResults    int `json:"total_results"`
}
