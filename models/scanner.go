package models

import (
	"time"

	"github.com/c1ayooo/4zreark/oid"
)

// NodeType represents different types of scanner nodes
type NodeType string

const (
	NodeTypeMaster   NodeType = "master"   // 控制面节点
	NodeTypeWorker   NodeType = "worker"   // 扫描节点
	NodeTypeGeneral  NodeType = "general"  // 通用扫描节点（历史值）
	NodeTypeSpecial  NodeType = "special"  // 专项扫描节点（历史值）
	NodeTypeInternal NodeType = "internal" // 内网节点（历史值）
)

// NodeStatus represents node status
type NodeStatus string

const (
	NodeStatusOnline   NodeStatus = "online"
	NodeStatusOffline  NodeStatus = "offline"
	NodeStatusBusy     NodeStatus = "busy"
	NodeStatusDisabled NodeStatus = "disabled"
)

// ScannerNode represents a distributed scanner node
type ScannerNode struct {
	ID          oid.ObjectID `json:"id" bson:"_id,omitempty"`
	NodeID      string       `json:"node_id" bson:"node_id"` // unique node identifier
	Name        string       `json:"name" bson:"name"`
	Description string       `json:"description" bson:"description"`
	Type        NodeType     `json:"type" bson:"type"`
	Status      NodeStatus   `json:"status" bson:"status"`

	// Node Info
	IP      string `json:"ip" bson:"ip"`
	Port    int    `json:"port" bson:"port"`
	Version string `json:"version" bson:"version"`

	// Capabilities
	Capabilities []string `json:"capabilities" bson:"capabilities"` // port_scan, vuln_scan, etc.
	MaxTasks     int      `json:"max_tasks" bson:"max_tasks"`
	CurrentTasks int      `json:"current_tasks" bson:"current_tasks"`

	// System Info
	SystemInfo NodeSystemInfo `json:"system_info" bson:"system_info"`

	// Heartbeat
	LastHeartbeat     time.Time `json:"last_heartbeat" bson:"last_heartbeat"`
	HeartbeatInterval int       `json:"heartbeat_interval" bson:"heartbeat_interval"` // seconds

	// TokenHash 是节点密钥的 SHA-256，密钥原文只在下发时出现一次。
	// 清空 token_hash 并写入 revoked_at 即可让节点无法再连接平台。
	TokenHash string     `json:"-" bson:"token_hash"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" bson:"revoked_at"`

	// Metadata
	Tags      []string  `json:"tags" bson:"tags"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// NodeSystemInfo represents node system information
type NodeSystemInfo struct {
	OS          string  `json:"os" bson:"os"`
	Arch        string  `json:"arch" bson:"arch"`
	CPUCores    int     `json:"cpu_cores" bson:"cpu_cores"`
	CPUUsage    float64 `json:"cpu_usage" bson:"cpu_usage"`
	MemoryTotal int64   `json:"memory_total" bson:"memory_total"` // bytes
	MemoryUsed  int64   `json:"memory_used" bson:"memory_used"`   // bytes
	MemoryUsage float64 `json:"memory_usage" bson:"memory_usage"` // percent
	DiskTotal   int64   `json:"disk_total" bson:"disk_total"`     // bytes
	DiskUsed    int64   `json:"disk_used" bson:"disk_used"`       // bytes
	DiskUsage   float64 `json:"disk_usage" bson:"disk_usage"`     // percent
}

// Plugin represents a scanner plugin
type Plugin struct {
	ID          oid.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string       `json:"name" bson:"name"`
	Description string       `json:"description" bson:"description"`
	Author      string       `json:"author" bson:"author"`
	Version     string       `json:"version" bson:"version"`
	Type        string       `json:"type" bson:"type"`         // scanner, processor, reporter
	Language    string       `json:"language" bson:"language"` // go, python

	// Plugin Configuration
	EntryFile string                 `json:"entry_file" bson:"entry_file"`
	Config    map[string]interface{} `json:"config" bson:"config"`

	// Dependencies
	Dependencies []string `json:"dependencies" bson:"dependencies"`

	// Status
	Enabled   bool   `json:"enabled" bson:"enabled"`
	Installed bool   `json:"installed" bson:"installed"`
	Source    string `json:"source" bson:"source"` // official, community, custom

	// Metadata
	Downloads int       `json:"downloads" bson:"downloads"`
	Rating    float64   `json:"rating" bson:"rating"`
	Tags      []string  `json:"tags" bson:"tags"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// FingerprintRule represents fingerprint detection rules
type FingerprintRule struct {
	ID       oid.ObjectID `json:"id" bson:"_id,omitempty"`
	Name     string       `json:"name" bson:"name"`
	Category string       `json:"category" bson:"category"` // cms, framework, server, os
	Version  string       `json:"version" bson:"version"`

	// Detection Rules
	Rules []FingerprintMatch `json:"rules" bson:"rules"`

	// Metadata
	Enabled   bool      `json:"enabled" bson:"enabled"`
	Source    string    `json:"source" bson:"source"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// FingerprintMatch represents a single fingerprint matching rule
type FingerprintMatch struct {
	Type     string `json:"type" bson:"type"`                   // header, body, title, icon_hash
	Key      string `json:"key,omitempty" bson:"key,omitempty"` // for header matching
	Pattern  string `json:"pattern" bson:"pattern"`             // regex pattern or hash value
	Operator string `json:"operator" bson:"operator"`           // contains, equals, regex, hash
}

// Dictionary represents wordlist dictionaries
type Dictionary struct {
	ID          oid.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string       `json:"name" bson:"name"`
	Type        string       `json:"type" bson:"type"` // subdomain, directory, username, password
	Description string       `json:"description" bson:"description"`
	FilePath    string       `json:"file_path" bson:"file_path"`
	LineCount   int          `json:"line_count" bson:"line_count"`
	IsBuiltin   bool         `json:"is_builtin" bson:"is_builtin"`
	CreatedBy   oid.ObjectID `json:"created_by" bson:"created_by"`
	CreatedAt   time.Time    `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at" bson:"updated_at"`
}

// Collection names for scanner components
const (
	CollectionNodes            = "scanner_nodes"
	CollectionPlugins          = "plugins"
	CollectionFingerprintRules = "fingerprint_rules"
	CollectionDictionaries     = "dictionaries"
)
