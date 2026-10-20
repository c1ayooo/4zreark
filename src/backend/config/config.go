package config

import (
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	JWT        JWTConfig        `mapstructure:"jwt"`
	MongoDB    MongoDBConfig    `mapstructure:"mongodb"`
	Postgres   PostgresConfig   `mapstructure:"postgres"`
	Scanner    ScannerConfig    `mapstructure:"scanner"`
	Log        LogConfig        `mapstructure:"log"`
	Alert      AlertConfig      `mapstructure:"alert"`
	ThirdParty ThirdPartyConfig `mapstructure:"thirdparty"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
}

type JWTConfig struct {
	Secret string `mapstructure:"secret"`
	Expire int    `mapstructure:"expire"`
	Issuer string `mapstructure:"issuer"`
}

type MongoDBConfig struct {
	URI      string `mapstructure:"uri"`
	Database string `mapstructure:"database"`
	Timeout  int    `mapstructure:"timeout"`
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
	Fofa   FofaConfig   `mapstructure:"fofa"`
	Hunter HunterConfig `mapstructure:"hunter"`
	Quake  QuakeConfig  `mapstructure:"quake"`
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
	})

	return cfg
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
