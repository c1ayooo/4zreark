package config

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	JWT        JWTConfig        `mapstructure:"jwt"`
	Postgres   PostgresConfig   `mapstructure:"postgres"`
	Scanner    ScannerConfig    `mapstructure:"scanner"`
	Node       NodeConfig       `mapstructure:"node"`
	Log        LogConfig        `mapstructure:"log"`
	Alert      AlertConfig      `mapstructure:"alert"`
	ThirdParty ThirdPartyConfig `mapstructure:"thirdparty"`
	AutoVerify AutoVerifyConfig `mapstructure:"auto_verify"`
}

// AutoVerifyConfig 是指纹命中后的自动 nuclei 最小验证。
// 默认关闭：会在真实目标上发起请求，必须显式开启。
type AutoVerifyConfig struct {
	Enabled     bool `mapstructure:"enabled"`
	RecheckDays int  `mapstructure:"recheck_days"`
	Concurrency int  `mapstructure:"concurrency"`
	RateLimit   int  `mapstructure:"rate_limit"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
	// PublicURL 平台对外访问地址（如 https://x.x.x.x:8080），通知消息里的
	// 「前往处置」按钮用它拼绝对链接；空 = 不渲染按钮。
	PublicURL string `mapstructure:"public_url"`
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
	RetryDelay  int `mapstructure:"retry_delay"`
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

type LogConfig struct {
	Level      string `mapstructure:"level"`
	File       string `mapstructure:"file"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

type AlertConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Types   []string `mapstructure:"types"`
}

type ThirdPartyConfig struct {
	Fofa    FofaConfig    `mapstructure:"fofa"`
	Hunter  HunterConfig  `mapstructure:"hunter"`
	Quake   QuakeConfig   `mapstructure:"quake"`
	ZoomEye ZoomEyeConfig `mapstructure:"zoomeye"`
	Shodan  ShodanConfig  `mapstructure:"shodan"`
	CrtSh   CrtShConfig   `mapstructure:"crtsh"`
}

type FofaConfig struct {
	Email string `mapstructure:"email"`
	Key   string `mapstructure:"key"`
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
	})

	return cfg
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
