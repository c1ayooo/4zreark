package models

import (
	"time"

	"github.com/c1ayooo/4zreark/oid"
)

// CruiseStatus 巡航任务状态
type CruiseStatus string

const (
	CruiseStatusEnabled  CruiseStatus = "enabled"  // 启用
	CruiseStatusDisabled CruiseStatus = "disabled" // 禁用
	CruiseStatusRunning  CruiseStatus = "running"  // 执行中
)

// 巡航目标来源：固定列表，或执行时从项目整体资产派生。
const (
	CruiseTargetSourceStatic  = "static"
	CruiseTargetSourceProject = "project"
)

// 巡航类型：scan 常规扫描任务（默认）；digital_assets 数字资产周期采集
// （遍历项目企业线索拉取 APP/小程序/公众号/新媒体，diff 后只把新增送候选池）。
const (
	CruiseKindScan          = "scan"
	CruiseKindDigitalAssets = "digital_assets"
)

// DigitalCruiseConfig 数字资产巡航的会话与容量配置。
// 定时执行没有请求上下文，凭据随任务配置存储（与平台内其它出网配置同级敏感项）。
type DigitalCruiseConfig struct {
	Provider    string `json:"provider" bson:"provider"`
	Username    string `json:"username" bson:"username"`
	Password    string `json:"password" bson:"password"`
	Cookie      string `json:"cookie" bson:"cookie"`
	ProxyURL    string `json:"proxy_url" bson:"proxy_url"`
	MaxEntities int    `json:"max_entities" bson:"max_entities"` // 单次采集企业数上限
	MaxAssets   int    `json:"max_assets" bson:"max_assets"`     // 单企业资产上限
}

// CruiseTask 巡航任务（定时自动扫描）
type CruiseTask struct {
	ID          oid.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID oid.ObjectID `json:"workspace_id" bson:"workspace_id"`
	// ProjectID 是巡航归属项目；扫描结果会并入该项目资产域。
	ProjectID int64 `json:"project_id" bson:"project_id"`
	// TargetSource 为 static 时使用 Targets；为 project 时每次执行按项目整体资产重新派生。
	TargetSource string       `json:"target_source" bson:"target_source"`
	// Kind 巡航类型：scan（默认，缺省为存量任务语义）| digital_assets。
	Kind   string              `json:"kind" bson:"kind"`
	Digital DigitalCruiseConfig `json:"digital" bson:"digital"`
	Name         string       `json:"name" bson:"name"`
	Description  string       `json:"description" bson:"description"`
	Status       CruiseStatus `json:"status" bson:"status"`

	// 定时配置
	CronExpr string `json:"cron_expr" bson:"cron_expr"` // Cron 表达式，如 "0 2 * * *" 每天凌晨2点
	Timezone string `json:"timezone" bson:"timezone"`   // 时区，如 "Asia/Shanghai"

	// 扫描目标
	Targets    []string `json:"targets" bson:"targets"`         // 固定目标；project 模式下仅作历史展示
	TargetType string   `json:"target_type" bson:"target_type"` // ip, domain, url, cidr

	// 扫描配置（复用 TaskConfig）
	TaskType TaskType   `json:"task_type" bson:"task_type"` // 任务类型
	Config   TaskConfig `json:"config" bson:"config"`       // 扫描配置

	// 通知配置
	NotifyOnComplete bool     `json:"notify_on_complete" bson:"notify_on_complete"` // 完成后通知
	NotifyOnVuln     bool     `json:"notify_on_vuln" bson:"notify_on_vuln"`         // 发现漏洞时通知
	NotifyChannels   []string `json:"notify_channels" bson:"notify_channels"`       // 通知渠道

	// 执行统计
	LastRunAt    time.Time `json:"last_run_at,omitempty" bson:"last_run_at,omitempty"`
	NextRunAt    time.Time `json:"next_run_at,omitempty" bson:"next_run_at,omitempty"`
	RunCount     int       `json:"run_count" bson:"run_count"`                           // 执行次数
	SuccessCount int       `json:"success_count" bson:"success_count"`                   // 成功次数
	FailCount    int       `json:"fail_count" bson:"fail_count"`                         // 失败次数
	LastTaskID   string    `json:"last_task_id,omitempty" bson:"last_task_id,omitempty"` // 最近一次任务ID
	LastStatus   string    `json:"last_status,omitempty" bson:"last_status,omitempty"`   // 最近一次执行状态

	// 元数据
	CreatedBy oid.ObjectID `json:"created_by" bson:"created_by"`
	Tags      []string     `json:"tags" bson:"tags"`
	CreatedAt time.Time    `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time    `json:"updated_at" bson:"updated_at"`
}

// CruiseTaskCreateRequest 创建巡航任务请求
type CruiseTaskCreateRequest struct {
	Name             string     `json:"name" binding:"required"`
	Description      string     `json:"description"`
	ProjectID        int64      `json:"project_id"`
	Kind             string     `json:"kind"` // scan（默认）| digital_assets
	TargetSource     string     `json:"target_source"`                // static | project
	CronExpr         string     `json:"cron_expr" binding:"required"` // Cron 表达式
	Timezone         string     `json:"timezone"`                     // 默认 Asia/Shanghai
	Targets          []string   `json:"targets"`                      // static 模式必填
	TargetType       string     `json:"target_type"`
	TaskType         TaskType   `json:"task_type"` // scan 类型必填
	Config           TaskConfig `json:"config"`
	Digital          DigitalCruiseConfig `json:"digital"`
	NotifyOnComplete bool       `json:"notify_on_complete"`
	NotifyOnVuln     bool       `json:"notify_on_vuln"`
	NotifyChannels   []string   `json:"notify_channels"`
	Tags             []string   `json:"tags"`
}

// CruiseTaskUpdateRequest 更新巡航任务请求
type CruiseTaskUpdateRequest struct {
	Name             *string     `json:"name"`
	Description      *string     `json:"description"`
	ProjectID        *int64      `json:"project_id"`
	TargetSource     *string     `json:"target_source"`
	CronExpr         *string     `json:"cron_expr"`
	Timezone         *string     `json:"timezone"`
	Targets          []string    `json:"targets"`
	TargetType       *string     `json:"target_type"`
	TaskType         *TaskType   `json:"task_type"`
	Config           *TaskConfig `json:"config"`
	Digital          *DigitalCruiseConfig `json:"digital"`
	NotifyOnComplete *bool       `json:"notify_on_complete"`
	NotifyOnVuln     *bool       `json:"notify_on_vuln"`
	NotifyChannels   []string    `json:"notify_channels"`
	Tags             []string    `json:"tags"`
}

// CruiseLog 巡航执行日志
type CruiseLog struct {
	ID          string       `json:"id"` // PG 是 bigserial，响应里本来就是字符串
	CruiseID    oid.ObjectID `json:"cruise_id" bson:"cruise_id"`
	TaskID      oid.ObjectID `json:"task_id" bson:"task_id"`
	Status      string       `json:"status" bson:"status"` // success, failed, running
	StartTime   time.Time    `json:"start_time" bson:"start_time"`
	EndTime     time.Time    `json:"end_time,omitempty" bson:"end_time,omitempty"`
	Duration    int64        `json:"duration" bson:"duration"` // 秒
	ResultCount int          `json:"result_count" bson:"result_count"`
	VulnCount   int          `json:"vuln_count" bson:"vuln_count"`
	Error       string       `json:"error,omitempty" bson:"error,omitempty"`
	CreatedAt   time.Time    `json:"created_at" bson:"created_at"`
}

// GetCronDescription 获取 Cron 表达式的中文描述
func GetCronDescription(cronExpr string) string {
	// 常用 Cron 表达式映射
	descriptions := map[string]string{
		"0 * * * *":    "每小时执行",
		"0 */2 * * *":  "每2小时执行",
		"0 */6 * * *":  "每6小时执行",
		"0 */12 * * *": "每12小时执行",
		"0 0 * * *":    "每天凌晨执行",
		"0 2 * * *":    "每天凌晨2点执行",
		"0 0 * * 0":    "每周日凌晨执行",
		"0 0 * * 1":    "每周一凌晨执行",
		"0 0 1 * *":    "每月1日凌晨执行",
		"0 0 1,15 * *": "每月1日和15日凌晨执行",
	}

	if desc, ok := descriptions[cronExpr]; ok {
		return desc
	}
	return cronExpr
}
