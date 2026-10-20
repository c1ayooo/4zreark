package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// CleanupService 处理失联站点的归档。
//
// 三条硬规则（v2 §8.5）：
//  1. 只归档、不物理删除；
//  2. 归档前必须**服务端复核一次**，探通了就不归档（避免因为一次网络抖动把资产抹掉）；
//  3. 每次归档都要落 operation_logs，能查到是谁在什么时候因为什么做的。
type CleanupService struct{}

func NewCleanupService() *CleanupService { return &CleanupService{} }

// CleanupReport 汇总一次归档。
type CleanupReport struct {
	Days       int      `json:"days"`
	DryRun     bool     `json:"dry_run"`
	Candidates int      `json:"candidates"`
	Rechecked  int      `json:"rechecked"`
	Kept       int      `json:"kept"`     // 复核后仍然可达，不归档
	Archived   int      `json:"archived"` // 已归档（dry_run 时为「将归档」）
	Failed     int      `json:"failed"`
	Items      []string `json:"items"`
}

// ArchiveLost 归档失联超过 days 天的站点。
func (s *CleanupService) ArchiveLost(ctx context.Context, days, limit int, dryRun bool, actor, ip string) (*CleanupReport, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	assets := repo.NewAssetRepo()
	verifier := NewVerifyService()

	if days <= 0 {
		days = 30
		_ = r.Pool().QueryRow(ctx, `select cleanup_days from connectivity_policies where id = 1`).Scan(&days)
	}

	candidates, err := assets.LostSitesForCleanup(ctx, days, limit)
	if err != nil {
		return nil, err
	}
	report := &CleanupReport{Days: days, DryRun: dryRun, Candidates: len(candidates), Items: []string{}}

	for _, c := range candidates {
		// 复核：仍然探得到就连 lost 一起撤掉（回到 reachable 由 ProbeSite 负责）
		probe, perr := verifier.ProbeSite(ctx, c.ID)
		report.Rechecked++
		if perr == nil && probe != nil && probe.Verdict == "reachable" {
			report.Kept++
			report.Items = append(report.Items, fmt.Sprintf("%s 复核可达，跳过", c.Host))
			continue
		}
		if dryRun {
			report.Archived++
			report.Items = append(report.Items, fmt.Sprintf("%s 将归档（dry-run）", c.Host))
			continue
		}
		if err := assets.ArchiveSite(ctx, c.ID, fmt.Sprintf("失联超过 %d 天", days)); err != nil {
			report.Failed++
			report.Items = append(report.Items, fmt.Sprintf("%s 归档失败: %v", c.Host, err))
			continue
		}
		report.Archived++
		report.Items = append(report.Items, fmt.Sprintf("%s 已归档", c.Host))

		// 审计：谁、什么时候、因为什么
		if err := r.LogOperation(ctx, repo.OperationLogInput{
			Username:  actor,
			Action:    "archive",
			Module:    "asset_governance",
			Target:    c.Host,
			Detail:    fmt.Sprintf("失联超过 %d 天，服务端复核仍不可达后归档（site_id=%d）", days, c.ID),
			IP:        ip,
			UserAgent: "governance/cleanup",
		}); err != nil {
			report.Items = append(report.Items, fmt.Sprintf("%s 审计日志写入失败: %v", c.Host, err))
		}
	}
	return report, nil
}

// ProtectSite 给站点设人工删除保护期。
func (s *CleanupService) ProtectSite(ctx context.Context, siteID int64, days int) error {
	r := repo.Default()
	if r == nil {
		return errors.New("数据层未初始化")
	}
	if days <= 0 {
		days = 90
	}
	return repo.NewAssetRepo().SetProtection(ctx, siteID, time.Now().AddDate(0, 0, days))
}
