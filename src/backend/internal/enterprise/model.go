// Package enterprise 提供企业信息收集能力（子公司/分支/投资/ICP 域名）。
// 设计参考 enscan_go（MIT）的收集思路：Provider 只负责上游请求，BFS 编排、
// 节点上限、深度、速率与审计由本包统一控制，不将上游原始响应透传给调用方。
package enterprise

import (
	"context"
	"time"
)

// CompanyRef 搜索结果中的企业引用。
type CompanyRef struct {
	ExtID string `json:"ext_id"`
	Name  string `json:"name"`
}

// DomainHit 上游返回的域名/备案线索。
type DomainHit struct {
	Domain   string `json:"domain"`
	Site     string `json:"site"`     // 网站名称
	ICP      string `json:"icp"`      // 备案号
	Evidence string `json:"evidence"` // 摘要证据（不含原始 banner）
}

// CompanyDetail 企业详情 + 关联域名。
type CompanyDetail struct {
	ExtID       string
	Name        string
	LegalPerson string
	OpenStatus  string
	Phone       string
	Email       string
	// RegisteredCapital 注册资本原文（如 "6500万元"），用于 CNVD 事件型等
	// 按资金规模筛目标的场景；只有 qcc 的详情页稳定返回该字段。
	RegisteredCapital string
	CreditCode        string
	Address           string
	Industry          string
	Domains           []DomainHit
}

// Entity 企业实体节点。
type Entity struct {
	ID          string    `json:"id"`
	JobID       string    `json:"job_id"`
	ExtID       string    `json:"ext_id"`
	Name        string    `json:"name"`
	EntityType  string    `json:"entity_type"` // root / branch / invest
	ParentExtID string    `json:"parent_ext_id"`
	Depth       int       `json:"depth"`
	LegalPerson string    `json:"legal_person"`
	OpenStatus  string    `json:"open_status"`
	Phone       string    `json:"phone"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
}

// CandidateAsset 采集到的候选域名资产，导入前 status=candidate。
// 项目级候选（信息收集发现面：icp_expand/scope_propose/fingerprint_links）JobID 为空串，
// 归属看 ProjectID；JobName 在查询层回落为来源标签。
type CandidateAsset struct {
	ID                string     `json:"id"`
	JobID             string     `json:"job_id"`
	ProjectID         string     `json:"project_id,omitempty"`
	Source            string     `json:"source,omitempty"` // enterprise / icp_expand / scope_propose / fingerprint_links
	JobName           string     `json:"job_name"`
	Kind              string     `json:"kind"` // domain
	Value             string     `json:"value"`
	EntityName        string     `json:"entity_name"`
	Evidence          string     `json:"evidence"`
	Status            string     `json:"status"` // candidate / authorized / imported / rejected(用户忽略，不再展示与重加)
	AuthorizedAt      *time.Time `json:"authorized_at,omitempty"`
	AuthorizedBy      string     `json:"authorized_by,omitempty"`
	FingerprintStatus string     `json:"fingerprint_status"`
	FingerprintError  string     `json:"fingerprint_error,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// Job 采集任务。
type Job struct {
	ID                   string     `json:"id"`
	ProjectID            string     `json:"project_id"`
	Owner                string     `json:"owner"`
	Provider             string     `json:"provider"`
	Keyword              string     `json:"keyword"`
	Status               string     `json:"status"` // running / done / error / canceled
	Depth                int        `json:"depth"`
	MaxNodes             int        `json:"max_nodes"`
	Nodes                int        `json:"nodes"`
	Entities             int        `json:"entities"`
	Domains              int        `json:"domains"`
	Imported             int        `json:"imported"`
	Error                string     `json:"error"`
	CreatedAt            time.Time  `json:"created_at"`
	FinishedAt           *time.Time `json:"finished_at"`
	FingerprintStatus    string     `json:"fingerprint_status"` // pending / running / completed / failed / skipped
	FingerprintTotal     int        `json:"fingerprint_total"`
	FingerprintCompleted int        `json:"fingerprint_completed"`
	FingerprintMatched   int        `json:"fingerprint_matched"`
	FingerprintFailed    int        `json:"fingerprint_failed"`
	FingerprintError     string     `json:"fingerprint_error"`
}

// FingerprintStats 是自动指纹回调返回的聚合结果。enterprise 不依赖具体扫描实现。
type FingerprintStats struct {
	Total     int
	Completed int
	Matched   int
	Failed    int
}

// FingerprintScanner 扫描候选域名并返回聚合统计。
type FingerprintScanner func(ctx context.Context, targets []string, projectID, ownerID string) (FingerprintStats, error)
