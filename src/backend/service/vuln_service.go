package service

import (
	"context"
	"errors"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/scanner/vulnscan"
)

// VulnService 的读写全部走 repo 层：这里不再出现集合名、bson 或游标。
type VulnService struct{}

func NewVulnService() *VulnService {
	return &VulnService{}
}

func (s *VulnService) store() (repo.VulnRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Vulns(), nil
}

func (s *VulnService) pocs() (repo.PocRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Pocs(), nil
}

// CreateVulnerability 创建漏洞
func (s *VulnService) CreateVulnerability(vuln *models.Vulnerability) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	vuln.Status = models.VulnStatusNew

	ctx, cancel := dbCtx()
	defer cancel()
	if err := store.Create(ctx, vuln); err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return errors.New("该漏洞已存在（同一模板与目标）")
		}
		return errors.New("创建漏洞失败")
	}
	return nil
}

// GetVulnByID 按 ID 取漏洞
func (s *VulnService) GetVulnByID(vulnID string) (*models.Vulnerability, error) {
	if !repo.ValidID(vulnID) {
		return nil, errors.New("无效的漏洞ID")
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	vuln, err := store.GetByID(ctx, vulnID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("漏洞不存在")
		}
		return nil, errors.New("查询漏洞失败")
	}
	return vuln, nil
}

// ListVulnerabilities 分页查询漏洞
func (s *VulnService) ListVulnerabilities(workspaceID, severity, status, keyword string, page, pageSize int) ([]*models.Vulnerability, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	vulns, total, err := store.List(ctx, repo.VulnFilter{
		WorkspaceID: workspaceID,
		Severity:    severity,
		Status:      status,
		Keyword:     keyword,
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		return nil, 0, errors.New("查询漏洞列表失败")
	}
	return vulns, total, nil
}

// UpdateVulnerability 更新漏洞字段
func (s *VulnService) UpdateVulnerability(vulnID string, updates map[string]interface{}) error {
	if !repo.ValidID(vulnID) {
		return errors.New("无效的漏洞ID")
	}
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.UpdateFields(ctx, vulnID, updates); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("漏洞不存在")
		}
		return errors.New("更新漏洞失败")
	}
	return nil
}

// DeleteVulnerability 删除漏洞
func (s *VulnService) DeleteVulnerability(vulnID string) error {
	if !repo.ValidID(vulnID) {
		return errors.New("无效的漏洞ID")
	}
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.Delete(ctx, vulnID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("漏洞不存在")
		}
		return errors.New("删除漏洞失败")
	}
	return nil
}

// MarkAsFixed 标记已修复
func (s *VulnService) MarkAsFixed(vulnID string, fixedBy string) error {
	return s.UpdateVulnerability(vulnID, map[string]interface{}{
		"status":   models.VulnStatusFixed,
		"fixed_at": time.Now(),
		"fixed_by": fixedBy,
	})
}

// MarkAsIgnored 标记忽略
func (s *VulnService) MarkAsIgnored(vulnID string) error {
	return s.UpdateVulnerability(vulnID, map[string]interface{}{
		"status": models.VulnStatusIgnored,
	})
}

// MarkAsFalsePositive 标记误报
func (s *VulnService) MarkAsFalsePositive(vulnID string) error {
	return s.UpdateVulnerability(vulnID, map[string]interface{}{
		"status": models.VulnStatusFalse,
	})
}

// GetVulnStats 按等级汇总，供报告摘要使用
func (s *VulnService) GetVulnStats(workspaceID string) (*models.ReportSummary, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	counts, total, err := store.SeverityCounts(ctx, workspaceID)
	if err != nil {
		return nil, errors.New("统计失败")
	}

	summary := &models.ReportSummary{
		TotalVulns:    int(total),
		CriticalCount: int(counts["critical"]),
		HighCount:     int(counts["high"]),
		MediumCount:   int(counts["medium"]),
		LowCount:      int(counts["low"]),
		InfoCount:     int(counts["info"]),
	}
	return summary, nil
}

// ---------------------------------------------------------------- POC

// CreatePOC 创建 POC
func (s *VulnService) CreatePOC(poc *models.POC) error {
	store, err := s.pocs()
	if err != nil {
		return err
	}
	poc.Enabled = true

	ctx, cancel := dbCtx()
	defer cancel()
	if err := store.Create(ctx, poc); err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return errors.New("POC 已存在（同一模板 ID）")
		}
		return errors.New("创建POC失败")
	}
	return nil
}

// GetPOCByID 按 ID 取 POC
func (s *VulnService) GetPOCByID(pocID string) (*models.POC, error) {
	if !repo.ValidID(pocID) {
		return nil, errors.New("无效的POC ID")
	}
	store, err := s.pocs()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	poc, err := store.GetByID(ctx, pocID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("POC不存在")
		}
		return nil, errors.New("查询POC失败")
	}
	return poc, nil
}

// ListPOCs 分页查询 POC
func (s *VulnService) ListPOCs(pocType, severity string, tags []string, keyword string, page, pageSize int) ([]*models.POC, int64, error) {
	store, err := s.pocs()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	pocs, total, err := store.List(ctx, repo.POCFilter{
		Type:     pocType,
		Severity: severity,
		Tags:     tags,
		Keyword:  keyword,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		return nil, 0, errors.New("查询POC列表失败")
	}
	return pocs, total, nil
}

// UpdatePOC 更新 POC
func (s *VulnService) UpdatePOC(pocID string, updates map[string]interface{}) error {
	if !repo.ValidID(pocID) {
		return errors.New("无效的POC ID")
	}
	store, err := s.pocs()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.UpdateFields(ctx, pocID, updates); err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return errors.New("POC 模板 ID 已被占用")
		}
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("POC不存在")
		}
		return errors.New("更新POC失败")
	}
	return nil
}

// DeletePOC 删除 POC
func (s *VulnService) DeletePOC(pocID string) error {
	if !repo.ValidID(pocID) {
		return errors.New("无效的POC ID")
	}
	store, err := s.pocs()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.Delete(ctx, pocID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("POC不存在")
		}
		return errors.New("删除POC失败")
	}
	return nil
}

// TogglePOC 启用或停用 POC
func (s *VulnService) TogglePOC(pocID string, enabled bool) error {
	return s.UpdatePOC(pocID, map[string]interface{}{"enabled": enabled})
}

// ---------------------------------------------------------------- 报告

// CreateReport 创建报告
func (s *VulnService) CreateReport(report *models.VulnReport) error {
	store, err := s.store()
	if err != nil {
		return err
	}

	if stats, err := s.GetVulnStats(report.WorkspaceID.Hex()); err == nil && stats != nil {
		report.Summary = *stats
	}

	ctx, cancel := dbCtx()
	defer cancel()
	if err := store.CreateReport(ctx, report); err != nil {
		return errors.New("创建报告失败")
	}
	return nil
}

// ListReports 分页查询报告
func (s *VulnService) ListReports(workspaceID string, page, pageSize int) ([]*models.VulnReport, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	reports, total, err := store.ListReports(ctx, workspaceID, page, pageSize)
	if err != nil {
		return nil, 0, errors.New("查询报告失败")
	}
	return reports, total, nil
}

// GetReportByID 按 ID 取报告
func (s *VulnService) GetReportByID(reportID string) (*models.VulnReport, error) {
	if !repo.ValidID(reportID) {
		return nil, errors.New("无效的报告ID")
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	report, err := store.GetReport(ctx, reportID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("报告不存在")
		}
		return nil, errors.New("查询报告失败")
	}
	return report, nil
}

// DeleteReport 删除报告
func (s *VulnService) DeleteReport(reportID string) error {
	if !repo.ValidID(reportID) {
		return errors.New("无效的报告ID")
	}
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.DeleteReport(ctx, reportID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("报告不存在")
		}
		return errors.New("删除报告失败")
	}
	return nil
}

// ---------------------------------------------------------------- 统计

// VulnStatistics 漏洞统计数据
type VulnStatistics struct {
	Total       int64                   `json:"total"`
	BySeverity  map[string]int64        `json:"by_severity"`
	ByStatus    map[string]int64        `json:"by_status"`
	ByType      map[string]int64        `json:"by_type"`
	RecentVulns []*models.Vulnerability `json:"recent_vulns"`
	TrendData   []TrendDataPoint        `json:"trend_data"`
}

// TrendDataPoint 趋势数据点
type TrendDataPoint struct {
	Date     string `json:"date"`
	Critical int64  `json:"critical"`
	High     int64  `json:"high"`
	Medium   int64  `json:"medium"`
	Low      int64  `json:"low"`
	Info     int64  `json:"info"`
}

// GetVulnStatistics 获取漏洞统计数据
func (s *VulnService) GetVulnStatistics(workspaceID string) (*VulnStatistics, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	sev, status, typ, total, err := store.GroupCounts(ctx, workspaceID)
	if err != nil {
		return nil, errors.New("统计失败")
	}

	stats := &VulnStatistics{
		Total:      total,
		BySeverity: sev,
		ByStatus:   status,
		ByType:     typ,
	}

	if recent, err := store.Recent(ctx, workspaceID, 10); err == nil {
		stats.RecentVulns = recent
	}
	stats.TrendData = s.buildTrend(store, workspaceID, 30)
	return stats, nil
}

// buildTrend 把聚合行铺成按天连续的序列，缺失的日期补零。
func (s *VulnService) buildTrend(store repo.VulnRepo, workspaceID string, days int) []TrendDataPoint {
	ctx, cancel := dbCtx()
	defer cancel()

	rows, err := store.Trend(ctx, workspaceID, days)
	if err != nil {
		return nil
	}

	byDate := make(map[string]*TrendDataPoint, len(rows))
	for _, row := range rows {
		point, ok := byDate[row.Date]
		if !ok {
			point = &TrendDataPoint{Date: row.Date}
			byDate[row.Date] = point
		}
		switch row.Severity {
		case "critical":
			point.Critical = row.Count
		case "high":
			point.High = row.Count
		case "medium":
			point.Medium = row.Count
		case "low":
			point.Low = row.Count
		case "info":
			point.Info = row.Count
		}
	}

	start := time.Now().AddDate(0, 0, -days)
	out := make([]TrendDataPoint, 0, days+1)
	for i := 0; i <= days; i++ {
		date := start.AddDate(0, 0, i).Format("2006-01-02")
		if point, ok := byDate[date]; ok {
			out = append(out, *point)
		} else {
			out = append(out, TrendDataPoint{Date: date})
		}
	}
	return out
}

// VerifyVulnerability 验证漏洞（重新扫描）
func (s *VulnService) VerifyVulnerability(vulnID string) (*models.Vulnerability, bool, error) {
	vuln, err := s.GetVulnByID(vulnID)
	if err != nil {
		return nil, false, err
	}

	verified := false
	if vulnscan.GlobalNucleiScanner != nil && vulnscan.GlobalNucleiScanner.IsAvailable() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		templateID := vuln.TemplateID
		if templateID == "" {
			templateID = vuln.Type
		}
		if templateID != "" && vuln.Target != "" {
			if result, err := vulnscan.GlobalNucleiScanner.VerifyVulnerability(ctx, vuln.Target, templateID); err == nil && result != nil {
				verified = true
			}
		}
	}

	updates := map[string]interface{}{"last_verified_at": time.Now()}
	if verified {
		updates["status"] = models.VulnStatusConfirmed
	}
	s.UpdateVulnerability(vulnID, updates)

	updated, _ := s.GetVulnByID(vulnID)
	return updated, verified, nil
}

// BatchUpdateStatus 批量更新状态
func (s *VulnService) BatchUpdateStatus(vulnIDs []string, status models.VulnStatus) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if _, err := store.BatchUpdateStatus(ctx, vulnIDs, string(status)); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("无有效的漏洞ID")
		}
		return errors.New("批量更新失败")
	}
	return nil
}

// GetVulnsByTaskID 根据任务 ID 获取漏洞
func (s *VulnService) GetVulnsByTaskID(taskID string, page, pageSize int) ([]*models.Vulnerability, int64, error) {
	if !repo.ValidID(taskID) {
		return nil, 0, errors.New("无效的任务ID")
	}
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	vulns, total, err := store.ListByTaskID(ctx, taskID, page, pageSize)
	if err != nil {
		return nil, 0, errors.New("查询漏洞失败")
	}
	return vulns, total, nil
}
