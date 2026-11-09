package pipeline

import "strings"

// ModuleSet 是「扫什么」的单一真源。
//
// 改造前各任务类型在 task_executor 里各自散落布尔开关，applyScanTypes 又用
// 「先全部清零再按列表置位」的方式覆盖，导致 takeover/api_probe 这类值要么
// 没有映射、要么被静默清掉。这里把模块选择收敛成结构体：
//   - CollectionModuleSet 产出「信息收集」默认全集（不含漏洞验证）；
//   - ModuleSetFromScanTypes 只负责把用户勾选映射成集合；
//   - ResolveDependencies 集中补齐模块间依赖；
//   - ApplyTo 一次性写回 PipelineConfig。
type ModuleSet struct {
	Subdomain   bool
	Takeover    bool
	HTTPProbe   bool
	PortScan    bool
	Fingerprint bool
	Crawler     bool
	JSAudit     bool
	APIProbe    bool
	DirScan     bool
	Sensitive   bool
	VulnScan    bool
	GogoPOC     bool

	// Explicit 表示用户显式给了模块列表（而不是走任务类型预设）。
	Explicit bool
}

// CollectionModuleSet 是「信息收集」默认模块集：除漏洞验证外全开。
//
// 明确排除：VulnScan（nuclei/PoC）、GogoPOC（端口模块内置 poc 旁路）。
// 这两项只能由调用方显式打开，避免「信息收集」名义下产生漏洞条目。
func CollectionModuleSet() ModuleSet {
	return ModuleSet{
		Subdomain:   true,
		Takeover:    true,
		HTTPProbe:   true,
		PortScan:    true,
		Fingerprint: true,
		Crawler:     true,
		JSAudit:     true,
		APIProbe:    true,
		DirScan:     true,
		Sensitive:   true,
		VulnScan:    false,
		GogoPOC:     false,
	}.ResolveDependencies()
}

// ModuleSetFromScanTypes 把任务配置里的模块列表映射为集合。
//
// 兼容旧值：service_detect/exposure_scan/clue_hunt 是独立任务类型，不进入
// 流水线模块集；domain_only/no_probe 是阶段编排专用值，用于「只收集域名、
// 不主动探活」的 S1 阶段。
func ModuleSetFromScanTypes(scanTypes []string) ModuleSet {
	ms := ModuleSet{Explicit: true}
	for _, raw := range scanTypes {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "subdomain":
			ms.Subdomain = true
			ms.HTTPProbe = true
		case "takeover":
			ms.Subdomain = true
			ms.Takeover = true
			ms.HTTPProbe = true
		case "domain_only", "no_probe":
			ms.Subdomain = true
			ms.HTTPProbe = false
		case "http_probe", "probe":
			ms.HTTPProbe = true
		case "port_scan", "portscan", "port":
			ms.PortScan = true
		case "fingerprint":
			ms.Fingerprint = true
		case "vuln_scan", "vulnscan", "vuln":
			ms.VulnScan = true
		case "crawler":
			ms.Crawler = true
		case "dir_scan", "dirscan", "directory":
			ms.DirScan = true
		case "sensitive":
			ms.Sensitive = true
		case "api_probe", "wih":
			ms.APIProbe = true
		case "js_audit", "js_secret", "jsaudit":
			ms.JSAudit = true
		case "gogo_poc", "port_poc":
			ms.GogoPOC = true
		}
	}
	return ms.ResolveDependencies()
}

// ResolveDependencies 补齐模块间依赖。只处理「少了上游整条链就断」的关系，
// 不在这里改速率或端口档位（那些属于任务配置）。
func (m ModuleSet) ResolveDependencies() ModuleSet {
	// 接管检测必须挂在子域枚举后面。
	if m.Takeover {
		m.Subdomain = true
	}
	// JS 审计只消费爬虫产出的 JS URL。
	if m.JSAudit {
		m.Crawler = true
	}
	// 指纹/爬虫/目录/敏感/接口/JS 都要吃 HTTP 端点，依赖端口发现。
	if m.Fingerprint || m.Crawler || m.DirScan || m.Sensitive || m.APIProbe || m.JSAudit || m.VulnScan {
		m.PortScan = true
	}
	// 除端口/子域外的模块需要指纹结果做服务判断。
	if m.Crawler || m.DirScan || m.Sensitive || m.APIProbe || m.JSAudit || m.VulnScan {
		m.Fingerprint = true
	}
	return m
}

// ApplyTo 把集合写回流水线配置。
//
// 注意：GogoPOC 单独控制端口模块是否把 gogo 内置 poc 命中写成漏洞结果；
// 它不受 VulnScan 影响，默认 false，只有显式勾选 gogo_poc 才打开。
func (m ModuleSet) ApplyTo(cfg *PipelineConfig) {
	if cfg == nil {
		return
	}
	cfg.SubdomainScan = m.Subdomain
	cfg.SubdomainCheckTakeover = m.Takeover
	cfg.SubdomainHTTPProbe = m.HTTPProbe
	cfg.HTTPProbeScan = m.HTTPProbe && !m.Subdomain
	cfg.PortScan = m.PortScan
	cfg.Fingerprint = m.Fingerprint
	cfg.VulnScan = m.VulnScan
	cfg.WebCrawler = m.Crawler
	cfg.DirScan = m.DirScan
	cfg.SensitiveScan = m.Sensitive
	cfg.ApiProbe = m.APIProbe
	cfg.JsAudit = m.JSAudit
	cfg.GogoPOC = m.GogoPOC
}
