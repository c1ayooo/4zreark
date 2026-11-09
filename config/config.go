package config

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

type Config struct {
	Server            ServerConfig       `mapstructure:"server"`
	JWT               JWTConfig          `mapstructure:"jwt"`
	Auth              AuthConfig         `mapstructure:"auth"`
	Postgres          PostgresConfig     `mapstructure:"postgres"`
	Scanner           ScannerConfig      `mapstructure:"scanner"`
	Node              NodeConfig         `mapstructure:"node"`
	ThirdParty        ThirdPartyConfig   `mapstructure:"thirdparty"`
	SiteLiveness      SiteLivenessConfig `mapstructure:"site_liveness"`
	FingerprintVerify AutoVerifyConfig   `mapstructure:"fingerprint_verify"`
	MCP               MCPConfig          `mapstructure:"mcp"`
	Sentinel          SentinelConfig     `mapstructure:"sentinel"`
	Collection        CollectionConfig   `mapstructure:"collection"`
	LLM               LLMConfig          `mapstructure:"llm"`
}

// CollectionConfig 是「信息收集」预设与阶段编排的开关/阈值。
// Enabled=false 时保持旧行为（按任务类型硬编码模块集），便于一键回滚。
type CollectionConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	Mode              string   `mapstructure:"mode"` // auto | full | staged
	DefaultModules    []string `mapstructure:"default_modules"`
	ExcludeModules    []string `mapstructure:"exclude_modules"`
	MaxTargetsForFull int      `mapstructure:"max_targets_for_full"`
	MinOnlineNodes    int      `mapstructure:"min_online_nodes"`
	MaxFailRate       float64  `mapstructure:"max_fail_rate"`
	StageTimeoutMin   int      `mapstructure:"stage_timeout_minutes"`
	SiteScope         string   `mapstructure:"site_scope"` // host | registrable_domain | project
	// GateMode：off 关闭；shadow 只判定不路由；enforce 允许规则层消费判定结果。
	GateMode    string `mapstructure:"gate_mode"`
	GateWorkers int    `mapstructure:"gate_workers"`
}

// Normalize 补齐信息收集默认值，避免各处重复判空。
func (c *CollectionConfig) Normalize() {
	if c == nil {
		return
	}
	switch c.Mode {
	case "auto", "full", "staged":
	default:
		c.Mode = "auto"
	}
	if len(c.DefaultModules) == 0 {
		c.DefaultModules = []string{
			"subdomain", "takeover", "http_probe", "port_scan", "fingerprint",
			"crawler", "js_audit", "api_probe", "dir_scan", "sensitive",
		}
	}
	if len(c.ExcludeModules) == 0 {
		c.ExcludeModules = []string{"vuln_scan", "bruteforce", "gogo_poc"}
	}
	if c.MaxTargetsForFull <= 0 {
		c.MaxTargetsForFull = 500
	}
	if c.MinOnlineNodes <= 0 {
		c.MinOnlineNodes = 1
	}
	if c.MaxFailRate <= 0 || c.MaxFailRate > 1 {
		c.MaxFailRate = 0.3
	}
	if c.StageTimeoutMin <= 0 {
		c.StageTimeoutMin = 360
	}
	if c.SiteScope == "" {
		c.SiteScope = "host"
	}
	switch c.GateMode {
	case "shadow", "enforce":
	default:
		c.GateMode = "off"
	}
	if c.GateWorkers <= 0 {
		c.GateWorkers = 4
	}
}

// SentinelConfig 是提交哨兵域的运行参数（v0.3 §8 / 附录 B）。
// 密钥类配置不落在本结构里，LLM 的 key 统一从环境变量读取。
type SentinelConfig struct {
	Enabled             bool     `mapstructure:"enabled"`
	MirrorDir           string   `mapstructure:"mirror_dir"`
	CloneHosts          []string `mapstructure:"clone_hosts"`
	CollectIntervalMin  int      `mapstructure:"collect_interval_minutes"`
	CollectWorkers      int      `mapstructure:"collect_workers"`
	JudgeWorkers        int      `mapstructure:"judge_workers"`
	MaxCommitsPerRun    int      `mapstructure:"max_commits_per_run"`
	TokenBudget         int      `mapstructure:"token_budget"`
	MaxHunkLines        int      `mapstructure:"max_hunk_lines"`
	JudgeModel          string   `mapstructure:"judge_model"`
	EnableAuditQueue    bool     `mapstructure:"enable_audit_queue"`
	QueuePollIntervalSy int      `mapstructure:"queue_poll_seconds"`
	// DeepAnalysis 高危发现二轮深审开关（Tier 2）：high/critical 命中后从本地
	// mirror 读变更文件全文做一次 LLM 细查，落 deep-analysis 草稿产物。
	// 未配置默认开启；会为每个高危发现多消耗一次 LLM 调用。
	DeepAnalysis *bool `mapstructure:"deep_analysis"`
	// AutoArtifacts 高危发现的自动验证产物配置：哪些产物在命中后自动草拟。
	// 全部落 draft，人工 verified 闸门不变；每项未配置默认开启。
	AutoArtifacts SentinelAutoArtifactsConfig `mapstructure:"auto_artifacts"`
	// PocVerify POC 靶场验证（Tier 3b）：docker 拉公开靶场镜像起隔离内网环境，
	// 在靶场上执行 verified 的 python-poc 判定可行性。worker 在 pocsmith 进程。
	PocVerify SentinelPocVerifyConfig `mapstructure:"poc_verify"`
}

// SentinelPocVerifyConfig 是 POC 靶场验证的参数。
type SentinelPocVerifyConfig struct {
	// Enabled 总开关；未配置默认开启。关闭时 verified python-poc 不自动入队验证。
	Enabled *bool `mapstructure:"enabled"`
	// PythonImage 执行 PoC 与就绪探测用的 Python 镜像。
	PythonImage string `mapstructure:"python_image"`
	// NucleiImage 引擎为 nuclei 时的执行镜像（含 nuclei 二进制）。
	NucleiImage string `mapstructure:"nuclei_image"`
	// ImageAllow 靶场镜像白名单前缀（AI 选的镜像必须命中其一）。
	// 默认 vulhub/ 与 ghcr.io/。
	ImageAllow []string `mapstructure:"image_allow"`
	// MaxWaitSeconds 靶场就绪探测上限（默认 120，封顶 300）。
	MaxWaitSeconds int `mapstructure:"max_wait_seconds"`
}

// Normalize 补齐 PocVerify 安全默认值。
func (p *SentinelPocVerifyConfig) Normalize() {
	if p.PythonImage == "" {
		p.PythonImage = "python:3.11-slim"
	}
	if p.NucleiImage == "" {
		p.NucleiImage = "projectdiscovery/nuclei:latest"
	}
	if len(p.ImageAllow) == 0 {
		p.ImageAllow = []string{"vulhub/", "ghcr.io/"}
	}
	if p.MaxWaitSeconds <= 0 {
		p.MaxWaitSeconds = 120
	}
	if p.MaxWaitSeconds > 300 {
		p.MaxWaitSeconds = 300
	}
}

// SentinelAutoArtifactsConfig 控制高危（high/critical/S 级）发现自动追加的
// 验证产物类型：python_poc=Python 验证脚本（kind=poc）、exploit_guide=利用文档
// （kind=report）、nuclei_web=web 漏洞类自动草拟 nuclei 模板（原仅 S 级）。
// 产物生成顺序：深审结论 → python-poc / exploit-guide / nuclei，均以深审
// 结论为输入（质量更高），深审不可用时退化为仅 diff 输入。
type SentinelAutoArtifactsConfig struct {
	PythonPOC    *bool `mapstructure:"python_poc"`
	ExploitGuide *bool `mapstructure:"exploit_guide"`
	NucleiWeb    *bool `mapstructure:"nuclei_web"`
}

// LLMConfig 是 OpenAI 兼容端点的接入参数。
// APIKey 不写在 yaml 里：由 APIKeyEnv 指定的变量名在启动时解析。
type LLMConfig struct {
	BaseURL             string  `mapstructure:"base_url"`
	APIKey              string  `mapstructure:"api_key"`
	APIKeyEnv           string  `mapstructure:"api_key_env"`
	Model               string  `mapstructure:"model"`
	TimeoutSeconds      int     `mapstructure:"timeout_seconds"`
	MaxRetries          int     `mapstructure:"max_retries"`
	Temperature         float64 `mapstructure:"temperature"`
	MaxTokens           int     `mapstructure:"max_tokens"`
	PromptCostPer1K     float64 `mapstructure:"prompt_cost_per_1k"`
	CompletionCostPer1K float64 `mapstructure:"completion_cost_per_1k"`
}

// Normalize 补齐哨兵配置的默认值，避免各处重复判空。
func (s *SentinelConfig) Normalize() {
	if s.MirrorDir == "" {
		s.MirrorDir = "data/sentinel-mirrors"
	}
	if s.CollectIntervalMin <= 0 {
		s.CollectIntervalMin = 5
	}
	if s.CollectWorkers <= 0 {
		s.CollectWorkers = 4
	}
	if s.JudgeWorkers <= 0 {
		s.JudgeWorkers = 8
	}
	if s.MaxCommitsPerRun <= 0 {
		s.MaxCommitsPerRun = 50
	}
	if s.TokenBudget <= 0 {
		s.TokenBudget = 10000
	}
	if s.MaxHunkLines <= 0 {
		s.MaxHunkLines = 40
	}
	if len(s.CloneHosts) == 0 {
		s.CloneHosts = []string{"github.com"}
	}
	// JudgeModel 是历史兼容字段：仅评测报告展示；实际判定模型由 LLM.Model /
	// 系统设置「模型接入」决定，避免两处配置各说各话。
	if s.JudgeModel == "" {
		s.JudgeModel = "gpt-4o-mini"
	}
}

// EffectiveAPIKey 先看 api_key_env 指向的变量，再退回直接配置的 api_key。
func (l *LLMConfig) EffectiveAPIKey() string {
	if l.APIKeyEnv != "" {
		if v := os.Getenv(l.APIKeyEnv); v != "" {
			return v
		}
	}
	return l.APIKey
}

// Normalize 补齐 LLM 默认值。
func (l *LLMConfig) Normalize() {
	if l.BaseURL == "" {
		l.BaseURL = "https://api.openai.com/v1"
	}
	if l.Model == "" {
		l.Model = "gpt-4o-mini"
	}
	if l.TimeoutSeconds <= 0 {
		l.TimeoutSeconds = 90
	}
	if l.MaxRetries < 0 {
		l.MaxRetries = 0
	}
	if l.MaxTokens <= 0 {
		l.MaxTokens = 2048
	}
}

// MCPConfig 是 MCP 接入的治理参数。RateLimitPerMin 只约束 tools/call，
// initialize / tools/list / ping 不扣；<=0 时回落默认值 60。
type MCPConfig struct {
	RateLimitPerMin int `mapstructure:"rate_limit_per_min"`
}

// AuthConfig 认证边界。公开注册默认关闭（安全审计 H1）：空注册码一律拒绝，
// 显式开启后新账号才允许无码注册——新账号默认只读角色，仍不带项目数据授权之外的权限。
type AuthConfig struct {
	AllowPublicRegistration bool `mapstructure:"allow_public_registration"`
}

// AutoVerifyConfig 是指纹命中后的自动 nuclei 最小验证（fingerprint_verify 段）。
// 默认关闭：会在真实目标上发起请求，必须显式开启。
type AutoVerifyConfig struct {
	Enabled     bool `mapstructure:"enabled"`
	RecheckDays int  `mapstructure:"recheck_days"`
	Concurrency int  `mapstructure:"concurrency"`
	RateLimit   int  `mapstructure:"rate_limit"`
}

// SiteLivenessConfig 是站点存活自动验证（site_liveness 段）：新扫描/导入的
// pending 站点后台按批次真实探测。Enabled 为 nil（未配置）时默认开启；
// 显式 false 关闭。ZRE_AUTOVERIFY_* 环境变量仍可单项覆盖（临时降载用）。
type SiteLivenessConfig struct {
	Enabled     *bool `mapstructure:"enabled"`
	Parallel    int   `mapstructure:"parallel"`
	BatchLimit  int   `mapstructure:"batch_limit"`
	IntervalSec int   `mapstructure:"interval_sec"`
	DelayMS     int   `mapstructure:"delay_ms"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
	// PublicURL 平台对外访问地址（如 https://x.x.x.x:8080），通知消息里的
	// 「前往处置」按钮用它拼绝对链接；空 = 不渲染按钮。
	PublicURL string `mapstructure:"public_url"`
	// TLS 证书/密钥：同时配置后主 Web 在 server.port 上直接以 HTTPS 提供
	// 服务（原生 TLS，无需反代）。两者必须成对出现，配一缺一拒绝启动。
	TLSCert string `mapstructure:"tls_cert"`
	TLSKey  string `mapstructure:"tls_key"`
	// ForceHTTPS 强制 HTTPS（安全审计 M11）：反向代理终止 TLS 的部署开启后，
	// 明文请求一律 301 到 https，并下发 HSTS 头。原生 TLS 模式自动生效。
	ForceHTTPS bool `mapstructure:"force_https"`
}

type JWTConfig struct {
	Secret string `mapstructure:"secret"`
	Expire int    `mapstructure:"expire"`
	Issuer string `mapstructure:"issuer"`
}

// PostgresConfig 是数据层唯一存储配置，键名与交接规格 §5 一致，不要改名。
type PostgresConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	Schema   string `mapstructure:"schema"`
	SSLMode  string `mapstructure:"sslmode"`
	MaxConns int    `mapstructure:"max_conns"`
	MinConns int    `mapstructure:"min_conns"`
}

type ScannerConfig struct {
	WorkerCount int `mapstructure:"worker_count"`
	Timeout     int `mapstructure:"timeout"`
	RetryCount  int `mapstructure:"retry_count"`
	// ForceCleanTerminalJobs 默认 false：终态任务的僵尸 River job 只 JobCancel，
	// 由 River 的 RescueStuckJobsAfter 回收；显式开启才保留旧强删（运维兜底）。
	ForceCleanTerminalJobs bool `mapstructure:"force_clean_terminal_jobs"`
}

// 节点角色。all 是单机默认值：控制面 + 本机扫描 worker。
const (
	NodeRoleAll    = "all"
	NodeRoleMaster = "master"
	NodeRoleWorker = "worker"
)

// DefaultNodeCapabilities 是节点默认上报的能力集合。
// 目前只用于展示与运维筛选，作业领取仍由 PG 队列决定。
var DefaultNodeCapabilities = []string{
	"subdomain", "port_scan", "fingerprint", "vuln_scan", "crawler", "dir_scan", "sensitive",
}

// NodeConfig 描述当前进程在集群里的身份。
// master/all 连接 PostgreSQL 并持有扫描队列；
// worker 只用 PlatformURL + Token 连平台，不接触数据库账号。
type NodeConfig struct {
	ID                string   `mapstructure:"id"`
	Name              string   `mapstructure:"name"`
	Role              string   `mapstructure:"role"`
	PlatformURL       string   `mapstructure:"platform_url"`
	Token             string   `mapstructure:"token"`
	Proxy             string   `mapstructure:"proxy"`
	PlatformCA        string   `mapstructure:"platform_ca"`
	GatewayPort       int      `mapstructure:"gateway_port"`
	GatewayHost       string   `mapstructure:"gateway_host"`
	TLSCert           string   `mapstructure:"tls_cert"`
	TLSKey            string   `mapstructure:"tls_key"`
	TLSCA             string   `mapstructure:"tls_ca"`
	TLSDir            string   `mapstructure:"tls_dir"`
	WindowsBinary     string   `mapstructure:"windows_binary"`
	RemBinary         string   `mapstructure:"rem_binary"`
	TunnelDir         string   `mapstructure:"tunnel_dir"`
	MaxTasks          int      `mapstructure:"max_tasks"`
	HeartbeatInterval int      `mapstructure:"heartbeat_interval"`
	Tags              []string `mapstructure:"tags"`
	Capabilities      []string `mapstructure:"capabilities"`
}

// Normalize 填充节点默认值。必须在启动时调用一次。
func (n *NodeConfig) Normalize() {
	hostname, _ := os.Hostname()
	if n.Name == "" {
		n.Name = hostname
	}
	if n.Name == "" {
		n.Name = "4zreark-node"
	}
	if n.ID == "" {
		n.ID = n.Name
	}
	switch n.Role {
	case NodeRoleAll, NodeRoleMaster, NodeRoleWorker:
	default:
		n.Role = NodeRoleAll
	}
	if n.HeartbeatInterval <= 0 {
		n.HeartbeatInterval = 30
	}
	if n.GatewayPort <= 0 {
		n.GatewayPort = 9443
	}
	if n.TLSDir == "" {
		n.TLSDir = "data/node-tls"
	}
	if len(n.Capabilities) == 0 {
		n.Capabilities = append([]string(nil), DefaultNodeCapabilities...)
	}
}

// RunsControlPlane 表示当前进程是否启动 Web/API、巡航与治理等单例任务。
func (n *NodeConfig) RunsControlPlane() bool {
	return n.Role == NodeRoleAll || n.Role == NodeRoleMaster
}

// RunsScanner 表示当前进程是否启动扫描 worker。
func (n *NodeConfig) RunsScanner() bool {
	return n.Role == NodeRoleAll || n.Role == NodeRoleWorker
}

// 说明：历史上的 log.*（slog 默认行为接管，无读者）与 alert.*（通知已迁移
// 到数据库 app_settings，代码零读取）配置段已删除；scanner.retry_delay 同因
// 无读者删除。若部署环境 yaml 里仍残留这些段，viper 会静默忽略，不影响启动。

type ThirdPartyConfig struct {
	Fofa    FofaConfig    `mapstructure:"fofa"`
	Hunter  HunterConfig  `mapstructure:"hunter"`
	Quake   QuakeConfig   `mapstructure:"quake"`
	ZoomEye ZoomEyeConfig `mapstructure:"zoomeye"`
	Shodan  ShodanConfig  `mapstructure:"shodan"`
	CrtSh   CrtShConfig   `mapstructure:"crtsh"`
}

type FofaConfig struct {
	Key string `mapstructure:"key"`
}

type HunterConfig struct {
	Key string `mapstructure:"key"`
}

type QuakeConfig struct {
	Key string `mapstructure:"key"`
}

type ZoomEyeConfig struct {
	Key string `mapstructure:"key"`
}

type ShodanConfig struct {
	Key string `mapstructure:"key"`
}

// CrtShConfig 证书透明源开关（T11：全进程只有这一个开关）。
type CrtShConfig struct {
	Enabled *bool `mapstructure:"enabled"`
}

// CrtShEnabled 证书透明源是否启用；未配置时默认开启。
func CrtShEnabled() bool {
	if cfg == nil || cfg.ThirdParty.CrtSh.Enabled == nil {
		return true
	}
	return *cfg.ThirdParty.CrtSh.Enabled
}

// Loaded 返回已加载的配置；未加载时返回 nil。
// 测试或可能在 LoadConfig 之前执行的代码用这个，不要用 GetConfig（它会 fatal）。
func Loaded() *Config { return cfg }

var (
	cfg  *Config
	once sync.Once
)

func LoadConfig(path string) *Config {
	once.Do(func() {
		viper.SetConfigFile(path)
		viper.SetConfigType("yaml")

		if err := viper.ReadInConfig(); err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}

		cfg = &Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			log.Fatalf("Failed to unmarshal config: %v", err)
		}

		applyPostgresEnv(cfg)
		applyNodeEnv(cfg)
		applySecurityEnv(cfg)
		applySentinelEnv(cfg)
		applyCollectionConfig(cfg)
		applyLLMEnv(cfg)
	})

	return cfg
}

// LoadConfigRaw 从内存字节加载配置。
// 节点零配置启动时配置来自 stdin（CONFIG_PATH=/dev/stdin），自更新重启必须把
// 同一份原文重新灌回 fd 0，所以调用方要先留存原始字节再交给这里解析。
func LoadConfigRaw(raw []byte) *Config {
	once.Do(func() {
		viper.SetConfigType("yaml")

		if err := viper.ReadConfig(bytes.NewReader(raw)); err != nil {
			log.Fatalf("Failed to read config from stdin: %v", err)
		}

		cfg = &Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			log.Fatalf("Failed to unmarshal config: %v", err)
		}

		applyPostgresEnv(cfg)
		applyNodeEnv(cfg)
		applySecurityEnv(cfg)
		applySentinelEnv(cfg)
		applyCollectionConfig(cfg)
		applyLLMEnv(cfg)
	})

	return cfg
}

// applySentinelEnv 应用提交哨兵的环境变量覆盖（ZRE_SENTINEL_*）。
func applySentinelEnv(c *Config) {
	if v := os.Getenv("ZRE_SENTINEL_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Sentinel.Enabled = b
		}
	}
	if v := os.Getenv("ZRE_SENTINEL_MIRROR_DIR"); v != "" {
		c.Sentinel.MirrorDir = v
	}
	if v := os.Getenv("ZRE_SENTINEL_COLLECT_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Sentinel.CollectWorkers = n
		}
	}
	if v := os.Getenv("ZRE_SENTINEL_JUDGE_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Sentinel.JudgeWorkers = n
		}
	}
	if v := os.Getenv("ZRE_SENTINEL_MAX_COMMITS_PER_RUN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Sentinel.MaxCommitsPerRun = n
		}
	}
	if v := os.Getenv("ZRE_SENTINEL_TOKEN_BUDGET"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Sentinel.TokenBudget = n
		}
	}
	if v := os.Getenv("ZRE_SENTINEL_JUDGE_MODEL"); v != "" {
		c.Sentinel.JudgeModel = v
	}
	c.Sentinel.Normalize()
}

// applyCollectionConfig 应用信息收集默认值与环境变量覆盖（ZRE_COLLECTION_*）。
func applyCollectionConfig(c *Config) {
	if v := os.Getenv("ZRE_COLLECTION_ENABLED"); v != "" {
		c.Collection.Enabled = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("ZRE_COLLECTION_MODE"); v != "" {
		c.Collection.Mode = v
	}
	c.Collection.Normalize()
}

// applyLLMEnv 应用 LLM 接入参数（ZRE_LLM_*）。密钥只从环境读，不写回配置文件。
func applyLLMEnv(c *Config) {
	if v := os.Getenv("ZRE_LLM_BASE_URL"); v != "" {
		c.LLM.BaseURL = v
	}
	if v := os.Getenv("ZRE_LLM_API_KEY"); v != "" {
		c.LLM.APIKey = v
	}
	if v := os.Getenv("ZRE_LLM_MODEL"); v != "" {
		c.LLM.Model = v
	}
	if v := os.Getenv("ZRE_LLM_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.LLM.TimeoutSeconds = n
		}
	}
	if v := os.Getenv("ZRE_LLM_MAX_RETRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.LLM.MaxRetries = n
		}
	}
	c.LLM.Normalize()
}

// applyNodeEnv 让容器/多节点部署可以只靠环境变量区分节点身份。
func applyNodeEnv(c *Config) {
	if v := os.Getenv("ZRE_NODE_ID"); v != "" {
		c.Node.ID = v
	}
	if v := os.Getenv("ZRE_NODE_NAME"); v != "" {
		c.Node.Name = v
	}
	if v := os.Getenv("ZRE_NODE_ROLE"); v != "" {
		c.Node.Role = v
	}
	if v := os.Getenv("ZRE_PLATFORM_URL"); v != "" {
		c.Node.PlatformURL = v
	}
	if v := os.Getenv("ZRE_NODE_TOKEN"); v != "" {
		c.Node.Token = v
	}
	if v := os.Getenv("ZRE_NODE_PROXY"); v != "" {
		c.Node.Proxy = v
	}
	if v := os.Getenv("ZRE_NODE_WINDOWS_BINARY"); v != "" {
		c.Node.WindowsBinary = v
	}
	if v := os.Getenv("ZRE_NODE_REM_BINARY"); v != "" {
		c.Node.RemBinary = v
	}
	if v := os.Getenv("ZRE_NODE_TUNNEL_DIR"); v != "" {
		c.Node.TunnelDir = v
	}
	if v := os.Getenv("ZRE_NODE_GATEWAY_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Node.GatewayPort = n
		}
	}
	if v := os.Getenv("ZRE_NODE_GATEWAY_HOST"); v != "" {
		c.Node.GatewayHost = v
	}
	if v := os.Getenv("ZRE_NODE_TLS_CERT"); v != "" {
		c.Node.TLSCert = v
	}
	if v := os.Getenv("ZRE_NODE_TLS_KEY"); v != "" {
		c.Node.TLSKey = v
	}
	if v := os.Getenv("ZRE_NODE_TLS_CA"); v != "" {
		c.Node.TLSCA = v
	}
	if v := os.Getenv("ZRE_NODE_TLS_DIR"); v != "" {
		c.Node.TLSDir = v
	}
	if v := os.Getenv("ZRE_NODE_PLATFORM_CA"); v != "" {
		c.Node.PlatformCA = v
	}
	if v := os.Getenv("ZRE_NODE_MAX_TASKS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Node.MaxTasks = n
		}
	}
	if v := os.Getenv("ZRE_NODE_HEARTBEAT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Node.HeartbeatInterval = n
		}
	}
}

// applySecurityEnv 应用安全边界相关环境变量（TLS / 强制 HTTPS / 注册开关），
// 优先级与其它段一致：环境变量 > 配置文件。
func applySecurityEnv(c *Config) {
	if v := os.Getenv("ZRE_TLS_CERT"); v != "" {
		c.Server.TLSCert = v
	}
	if v := os.Getenv("ZRE_TLS_KEY"); v != "" {
		c.Server.TLSKey = v
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ZRE_FORCE_HTTPS"))) {
	case "1", "true", "yes", "on":
		c.Server.ForceHTTPS = true
	case "0", "false", "no", "off":
		c.Server.ForceHTTPS = false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ZRE_ALLOW_PUBLIC_REGISTRATION"))) {
	case "1", "true", "yes", "on":
		c.Auth.AllowPublicRegistration = true
	case "0", "false", "no", "off":
		c.Auth.AllowPublicRegistration = false
	}
}

// applyPostgresEnv 按交接规格 §5 的覆盖顺序应用环境变量。
func applyPostgresEnv(c *Config) {
	if v := os.Getenv("ZRE_PG_HOST"); v != "" {
		c.Postgres.Host = v
	}
	if v := os.Getenv("ZRE_PG_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Postgres.Port = n
		}
	}
	if v := os.Getenv("ZRE_PG_USER"); v != "" {
		c.Postgres.User = v
	}
	if v := os.Getenv("ZRE_PG_PASSWORD"); v != "" {
		c.Postgres.Password = v
	}
	if v := os.Getenv("ZRE_PG_DBNAME"); v != "" {
		c.Postgres.DBName = v
	}
	if v := os.Getenv("ZRE_PG_SCHEMA"); v != "" {
		c.Postgres.Schema = v
	}
	if v := os.Getenv("ZRE_PUBLIC_URL"); v != "" {
		c.Server.PublicURL = v
	}
	if v := os.Getenv("ZRE_JWT_SECRET"); v != "" {
		c.JWT.Secret = v
	}
}

// DefaultJWTSecret 是 config.yaml 随仓库分发的默认签名密钥。
// 入库的默认值等于任何人都能签出合法 admin JWT，控制面启动时必须检测。
const DefaultJWTSecret = "4zreark-secret-key-change-in-production"

// JWTSecretIsDefault 报告当前签名密钥是否还是随仓库分发的默认值。
func (j *JWTConfig) JWTSecretIsDefault() bool {
	return j.Secret == "" || j.Secret == DefaultJWTSecret
}

// DSN 拼装 PostgreSQL 连接串；search_path 走启动参数，SQL 里因此不用写 schema 前缀。
func (p *PostgresConfig) DSN() string {
	schema := p.Schema
	if schema == "" {
		schema = "public"
	}
	dsn := "host=" + p.Host +
		" port=" + strconv.Itoa(p.Port) +
		" user=" + p.User +
		" dbname=" + p.DBName +
		" sslmode=" + p.SSLMode +
		" search_path=" + schema
	if p.Password != "" {
		dsn += " password=" + p.Password
	}
	return dsn
}

func GetConfig() *Config {
	if cfg == nil {
		log.Fatal("Config not loaded. Call LoadConfig first.")
	}
	return cfg
}
