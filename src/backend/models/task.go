package models

import (
	"time"

	"github.com/c1ayooo/4zreark/oid"
)

// TaskType represents different types of scan tasks
type TaskType string

const (
	TaskTypeAssetDiscovery TaskType = "asset_discovery"
	TaskTypePortScan       TaskType = "port_scan"
	TaskTypeFingerprint    TaskType = "fingerprint"
	TaskTypeVulnScan       TaskType = "vuln_scan"
	TaskTypeSubdomain      TaskType = "subdomain"
	TaskTypeTakeover       TaskType = "takeover" // 子域名接管检测
	TaskTypeDirScan        TaskType = "dir_scan"
	TaskTypeCrawler        TaskType = "crawler"
	TaskTypeBruteforce     TaskType = "bruteforce"
	TaskTypeMonitor        TaskType = "monitor"
	TaskTypeFull           TaskType = "full"
	TaskTypeCustom         TaskType = "custom" // 用户自定义多种扫描类型组合

	// 协议识别与无凭据暴露面（reconkit T5）。
	// service_detect 是前端历史值，语义与 service_identify 相同。
	TaskTypeServiceID     TaskType = "service_identify"
	TaskTypeServiceDetect TaskType = "service_detect"
	TaskTypeExposure      TaskType = "exposure_scan"

	// 存量线索（reconkit T7）：Wayback 遗留端点 / CDN 源站 / 云资源 / SaaS。
	TaskTypeClueHunt TaskType = "clue_hunt"
)

// TaskStatus represents task execution status
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusPaused    TaskStatus = "paused"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// Task represents a scan task
type Task struct {
	ID          oid.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID oid.ObjectID `json:"workspace_id" bson:"workspace_id"`
	// ProjectID 是资产归属项目（projects.id）。0 = 未归属：历史任务兼容，
	// 这类任务的扫描结果不会自动并入资产域。
	ProjectID   int64      `json:"project_id" bson:"project_id"`
	Name        string     `json:"name" bson:"name"`
	Description string     `json:"description" bson:"description"`
	Type        TaskType   `json:"type" bson:"type"`
	Status      TaskStatus `json:"status" bson:"status"`

	// Target Configuration
	Targets    []string `json:"targets" bson:"targets"`         // IPs, domains, URLs
	TargetType string   `json:"target_type" bson:"target_type"` // ip, domain, url, cidr

	// Task Configuration
	Config TaskConfig `json:"config" bson:"config"`

	// Schedule Configuration
	IsScheduled bool   `json:"is_scheduled" bson:"is_scheduled"`
	CronExpr    string `json:"cron_expr,omitempty" bson:"cron_expr,omitempty"`

	// Execution Info
	Progress        int                    `json:"progress" bson:"progress"`                                     // 0-100
	ProgressDetails map[string]interface{} `json:"progress_details,omitempty" bson:"progress_details,omitempty"` // 详细进度信息
	NodeID          string                 `json:"node_id" bson:"node_id"`                                       // assigned scanner node
	StartedAt       time.Time              `json:"started_at,omitempty" bson:"started_at,omitempty"`
	CompletedAt     time.Time              `json:"completed_at,omitempty" bson:"completed_at,omitempty"`

	// Results Summary
	ResultStats TaskResultStats `json:"result_stats" bson:"result_stats"`

	// Retry Info
	RetryCount int    `json:"retry_count" bson:"retry_count"`
	LastError  string `json:"last_error,omitempty" bson:"last_error,omitempty"`

	// Metadata
	CreatedBy oid.ObjectID `json:"created_by" bson:"created_by"`
	Tags      []string     `json:"tags" bson:"tags"`
	CreatedAt time.Time    `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time    `json:"updated_at" bson:"updated_at"`
}

// TaskConfig represents task configuration options
type TaskConfig struct {
	// Scan Types (pipeline)
	ScanTypes []string `json:"scan_types,omitempty" bson:"scan_types,omitempty"` // port_scan, subdomain, fingerprint, vuln_scan, crawler, dir_scan

	// Port Scan Config
	PortScanMode string `json:"port_scan_mode,omitempty" bson:"port_scan_mode,omitempty"` // quick, full, top1000, custom
	PortRange    string `json:"port_range,omitempty" bson:"port_range,omitempty"`         // e.g., "1-1000", "top100"

	// Subdomain Config
	SubdomainDict string `json:"subdomain_dict,omitempty" bson:"subdomain_dict,omitempty"`
	// SubdomainDictID 指向前端配置的子域字典（dictionaries.id）；设置后覆盖内置词表。
	SubdomainDictID string `json:"subdomain_dict_id,omitempty" bson:"subdomain_dict_id,omitempty"`
	UsePassive      bool   `json:"use_passive,omitempty" bson:"use_passive,omitempty"`
	// 指针类型：nil 表示「未显式配置」→ 默认开启；显式 false 才关闭。
	SubdomainPermute   *bool `json:"subdomain_permute,omitempty" bson:"subdomain_permute,omitempty"`
	SubdomainArtifacts *bool `json:"subdomain_artifacts,omitempty" bson:"subdomain_artifacts,omitempty"`

	// Third-party API Config (for subdomain enumeration)
	UseThirdParty     bool     `json:"use_thirdparty,omitempty" bson:"use_thirdparty,omitempty"`         // 是否使用第三方 API
	ThirdPartySources []string `json:"thirdparty_sources,omitempty" bson:"thirdparty_sources,omitempty"` // fofa, hunter, quake, crtsh, securitytrails
	// EngineQueryMaxPerEngine 单任务内每引擎查询上限（防烧额度）。
	// master 建任务时按「当日引擎余额」收紧后下发；0=用流水线默认。
	EngineQueryMaxPerEngine int    `json:"engine_query_max_per_engine,omitempty" bson:"engine_query_max_per_engine,omitempty"`
	FofaEmail               string `json:"fofa_email,omitempty" bson:"fofa_email,omitempty"`
	FofaKey                 string `json:"fofa_key,omitempty" bson:"fofa_key,omitempty"`
	HunterKey               string `json:"hunter_key,omitempty" bson:"hunter_key,omitempty"`
	QuakeKey                string `json:"quake_key,omitempty" bson:"quake_key,omitempty"`

	// Fingerprint Config
	EnableFingerprint bool `json:"enable_fingerprint,omitempty" bson:"enable_fingerprint,omitempty"`

	// Vuln Scan Config
	POCIDs         []string `json:"poc_ids,omitempty" bson:"poc_ids,omitempty"`
	POCTags        []string `json:"poc_tags,omitempty" bson:"poc_tags,omitempty"`
	SeverityFilter []string `json:"severity_filter,omitempty" bson:"severity_filter,omitempty"`

	// Dir Scan Config
	DirDict string `json:"dir_dict,omitempty" bson:"dir_dict,omitempty"`
	// DirDictID 指向前端配置的目录字典（dictionaries.id）；设置后覆盖 spray 默认词表。
	DirDictID  string `json:"dir_dict_id,omitempty" bson:"dir_dict_id,omitempty"`
	Extensions string `json:"extensions,omitempty" bson:"extensions,omitempty"`

	// Wordlists 是 master 派单前物化好的词表内容。
	// 节点不连数据库，只有把条目随任务下发，任务级字典才能在分布式下生效。
	SubdomainWordlist []string `json:"subdomain_wordlist,omitempty" bson:"subdomain_wordlist,omitempty"`
	DirWordlist       []string `json:"dir_wordlist,omitempty" bson:"dir_wordlist,omitempty"`

	// Bruteforce Config
	ServiceType string `json:"service_type,omitempty" bson:"service_type,omitempty"`
	UserDict    string `json:"user_dict,omitempty" bson:"user_dict,omitempty"`
	PassDict    string `json:"pass_dict,omitempty" bson:"pass_dict,omitempty"`

	// Crawler Config
	MaxDepth       int  `json:"max_depth,omitempty" bson:"max_depth,omitempty"`
	MaxPages       int  `json:"max_pages,omitempty" bson:"max_pages,omitempty"`
	FollowRedirect bool `json:"follow_redirect,omitempty" bson:"follow_redirect,omitempty"`

	// Rate Control 节奏控制（除漏洞扫描外全模块生效；0 表示用默认值）
	RatePerSec    int `json:"rate_per_sec,omitempty" bson:"rate_per_sec,omitempty"`       // 每秒请求上限
	TargetDelayMs int `json:"target_delay_ms,omitempty" bson:"target_delay_ms,omitempty"` // 单目标间隔（毫秒）

	// General Config
	Threads     int      `json:"threads,omitempty" bson:"threads,omitempty"`
	Timeout     int      `json:"timeout,omitempty" bson:"timeout,omitempty"`
	Proxy       string   `json:"proxy,omitempty" bson:"proxy,omitempty"`
	VerifySSL   bool     `json:"verify_ssl,omitempty" bson:"verify_ssl,omitempty"`
	ExcludeList []string `json:"exclude_list,omitempty" bson:"exclude_list,omitempty"`

	// 资产入库开关。nil = 按 scanTypes 推导：
	//   端口扫描 -> 端口；爬虫/目录 -> URL；指纹/服务识别 -> 技术栈与图标。
	IngestPorts        *bool `json:"ingest_ports,omitempty" bson:"ingest_ports,omitempty"`
	IngestURLs         *bool `json:"ingest_urls,omitempty" bson:"ingest_urls,omitempty"`
	IngestFingerprints *bool `json:"ingest_fingerprints,omitempty" bson:"ingest_fingerprints,omitempty"`
	IngestIcons        *bool `json:"ingest_icons,omitempty" bson:"ingest_icons,omitempty"`
}

func (c TaskConfig) hasScanType(name string) bool {
	for _, t := range c.ScanTypes {
		if t == name {
			return true
		}
	}
	return false
}

// WantsPorts 决定端口结果是否进资产域。
func (c TaskConfig) WantsPorts(taskType TaskType) bool {
	if c.IngestPorts != nil {
		return *c.IngestPorts
	}
	if c.hasScanType("port_scan") {
		return true
	}
	switch taskType {
	case TaskTypePortScan, TaskTypeFull, TaskTypeAssetDiscovery:
		return true
	}
	return false
}

// WantsURLs 决定爬虫/目录扫描发现的 URL 是否进资产域。
func (c TaskConfig) WantsURLs(taskType TaskType) bool {
	if c.IngestURLs != nil {
		return *c.IngestURLs
	}
	if c.hasScanType("crawler") || c.hasScanType("dir_scan") {
		return true
	}
	switch taskType {
	case TaskTypeCrawler, TaskTypeDirScan, TaskTypeFull:
		return true
	}
	return false
}

// WantsFingerprints 决定技术栈/指纹是否随资产回写。爬虫和目录扫描会自动开指纹阶段。
func (c TaskConfig) WantsFingerprints(taskType TaskType) bool {
	if c.IngestFingerprints != nil {
		return *c.IngestFingerprints
	}
	if c.hasScanType("fingerprint") || c.hasScanType("service_detect") ||
		c.hasScanType("crawler") || c.hasScanType("dir_scan") {
		return true
	}
	switch taskType {
	case TaskTypeFingerprint, TaskTypeServiceID, TaskTypeServiceDetect,
		TaskTypeCrawler, TaskTypeDirScan, TaskTypeFull:
		return true
	}
	return false
}

// WantsIcons 默认跟随指纹阶段；也可以单独关闭图标入库。
func (c TaskConfig) WantsIcons(taskType TaskType) bool {
	if c.IngestIcons != nil {
		return *c.IngestIcons
	}
	return c.WantsFingerprints(taskType)
}

// TaskResultStats represents task result statistics
type TaskResultStats struct {
	TotalTargets     int `json:"total_targets" bson:"total_targets"`
	ScannedTargets   int `json:"scanned_targets" bson:"scanned_targets"`
	DiscoveredAssets int `json:"discovered_assets" bson:"discovered_assets"`
	DiscoveredVulns  int `json:"discovered_vulns" bson:"discovered_vulns"`
	DiscoveredPorts  int `json:"discovered_ports" bson:"discovered_ports"`
	// 用于断点续扫 - 记录已完成扫描的目标索引
	LastScannedIndex int `json:"last_scanned_index" bson:"last_scanned_index"`
	// 记录已完成的扫描阶段（用于 full 类型任务）
	CompletedStages []string `json:"completed_stages,omitempty" bson:"completed_stages,omitempty"`
}

// TaskTemplate represents reusable task templates
type TaskTemplate struct {
	ID          oid.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID oid.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Name        string       `json:"name" bson:"name"`
	Description string       `json:"description" bson:"description"`
	Type        TaskType     `json:"type" bson:"type"`
	Config      TaskConfig   `json:"config" bson:"config"`
	IsPublic    bool         `json:"is_public" bson:"is_public"`
	CreatedBy   oid.ObjectID `json:"created_by" bson:"created_by"`
	CreatedAt   time.Time    `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at" bson:"updated_at"`
}

// TaskLog represents task execution logs
type TaskLog struct {
	// id 在 PG 里是 bigserial，用字符串承载，响应体里仍是字符串
	ID        string       `json:"id" bson:"_id,omitempty"`
	TaskID    oid.ObjectID `json:"task_id" bson:"task_id"`
	Level     string       `json:"level" bson:"level"` // info, warn, error
	Message   string       `json:"message" bson:"message"`
	Detail    string       `json:"detail,omitempty" bson:"detail,omitempty"`
	CreatedAt time.Time    `json:"created_at" bson:"created_at"`
}

// Collection names for tasks
const (
	CollectionTasks         = "tasks"
	CollectionTaskTemplates = "task_templates"
	CollectionTaskLogs      = "task_logs"
)
