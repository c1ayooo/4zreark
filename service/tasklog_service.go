package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 任务日志（统一动作日志）：跨源聚合 task_logs / icp_queries / enterprise_jobs，
// 按功能分类筛选（子域名收集/ICP查询/端口扫描/企业采集/……），支持自动清空时段。
// 数据不是"另记一份"：运行日志落 task_logs（执行器全链路埋点），
// ICP 查询与企业采集直接聚合其记录表——动作发生即有日志。

const (
	TaskLogSettingsKey       = "tasklog.retention_days"
	TaskLogRetentionDefault  = 14
	taskLogRetentionInterval = time.Hour
)

type TaskLogFilter struct {
	ProjectID int64  `json:"project_id"`
	Category  string `json:"category"`
	Level     string `json:"level"`
	Query     string `json:"q"`
	Page      int    `json:"page"`
	PageSize  int    `json:"page_size"`
}

type TaskLogService struct{}

func NewTaskLogService() *TaskLogService { return &TaskLogService{} }

func (s *TaskLogService) repo() (repo.TaskRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Tasks(), nil
}

// List 跨源聚合的动作日志分页。
func (s *TaskLogService) List(ctx context.Context, f TaskLogFilter) ([]*repo.ActionLogRow, int64, error) {
	tasks, err := s.repo()
	if err != nil {
		return nil, 0, err
	}
	return tasks.ListActionLogs(ctx, f.ProjectID, f.Category, f.Level, f.Query, f.Page, f.PageSize)
}

// RetentionDays 自动清空时段（天）。app_settings 未配置时默认 14 天。
func (s *TaskLogService) RetentionDays(ctx context.Context) int {
	r := repo.Default()
	if r == nil {
		return TaskLogRetentionDefault
	}
	var days int
	if ok, err := r.Settings().Get(ctx, TaskLogSettingsKey, &days); err == nil && ok && days >= 1 && days <= 365 {
		return days
	}
	return TaskLogRetentionDefault
}

// SetRetentionDays 设置自动清空时段并立即按新时段清理一次。
func (s *TaskLogService) SetRetentionDays(ctx context.Context, days int) (purged int64, err error) {
	if days < 1 || days > 365 {
		return 0, errors.New("留存天数只能是 1–365")
	}
	r := repo.Default()
	if r == nil {
		return 0, errors.New("数据层未初始化")
	}
	if err := r.Settings().Set(ctx, TaskLogSettingsKey, days); err != nil {
		return 0, err
	}
	return r.Tasks().PurgeTaskLogs(ctx, days)
}

// PurgeNow 立即按当前留存时段清理。
func (s *TaskLogService) PurgeNow(ctx context.Context) (int64, error) {
	r := repo.Default()
	if r == nil {
		return 0, errors.New("数据层未初始化")
	}
	return r.Tasks().PurgeTaskLogs(ctx, s.RetentionDays(ctx))
}

// StartRetention 启动每小时一次的自动清空（进程启动时调用一次）。
func (s *TaskLogService) StartRetention() {
	go func() {
		ticker := time.NewTicker(taskLogRetentionInterval)
		defer ticker.Stop()
		for range ticker.C {
			r := repo.Default()
			if r == nil {
				continue
			}
			n, err := r.Tasks().PurgeTaskLogs(context.Background(), s.RetentionDays(context.Background()))
			if err != nil {
				log.Printf("[tasklog] 自动清理失败: %v", err)
			} else if n > 0 {
				log.Printf("[tasklog] 自动清理 %d 条过期日志", n)
			}
		}
	}()
}


// moduleCategory 流水线模块名 → 功能分类。
func moduleCategory(module string) string {
	switch module {
	case "SubdomainScan", "DomainVerify":
		return "subdomain"
	case "PortPreparation", "PortScan":
		return "port_scan"
	case "Fingerprint":
		return "fingerprint"
	case "Crawler", "JSAudit":
		return "crawler"
	case "DirScan":
		return "dir_scan"
	case "Sensitive":
		return "sensitive"
	case "VulnScan":
		return "vuln_scan"
	}
	return "system"
}

// stageLabel 模块名的中文阶段标签。
func stageLabel(module string) string {
	labels := map[string]string{
		"SubdomainScan": "子域名收集", "DomainVerify": "域名验证",
		"PortPreparation": "端口预处理", "PortScan": "端口扫描",
		"Fingerprint": "指纹识别", "Crawler": "Web 爬虫",
		"DirScan": "目录扫描", "Sensitive": "敏感信息",
		"VulnScan": "漏洞扫描", "JSAudit": "JS 审计",
	}
	if l, ok := labels[module]; ok {
		return l
	}
	return module
}

// LogAction 写一条动作日志（埋点统一入口）。
// category: subdomain/port_scan/fingerprint/crawler/dir_scan/vuln_scan/
//           service_identify/exposure_scan/clue_hunt/icp/enterprise/system
func LogAction(category, level, message string) {
	r := repo.Default()
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 非任务动作借道 task_logs：task_id 置 24 个 0（无关联任务的系统动作）
	if err := r.Tasks().AddLogCategory(ctx, strings.Repeat("0", 24), category, level, message, ""); err != nil {
		log.Printf("[tasklog] 写入失败: %v", err)
	}
}

// LogTaskAction 写任务关联的动作日志（category 通常取任务类型或阶段名）。
func LogTaskAction(taskID, category, level, message string) {
	r := repo.Default()
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Tasks().AddLogCategory(ctx, taskID, category, level, message, ""); err != nil {
		log.Printf("[tasklog] 写入失败: %v", err)
	}
}

// FormatDurationSeconds 秒数转人类可读时长（日志文案用）。
func FormatDurationSeconds(sec int64) string {
	d := time.Duration(sec) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
