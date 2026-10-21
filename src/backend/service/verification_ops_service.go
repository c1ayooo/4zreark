package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// VerificationOpsService 是验证域的操作面：跨站点历史、强制复验、
// 批量核验预览、失联站点删除。探测本身复用 VerifyService，不另写一套判定。
//
// 两条安全边界：
//   - 删除前必须逐条真实复核，复核可达或判不出真假一律跳过；
//   - 每次人工干预都写 operation_logs，审计里能查到操作者、IP 与原因。
var ErrVerificationInput = errors.New("验证操作参数错误")

type VerificationOpsService struct {
	probes *VerifyService
}

func NewVerificationOpsService() *VerificationOpsService {
	return &VerificationOpsService{probes: NewVerifyService()}
}

func (s *VerificationOpsService) assets() (*repo.AssetRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.NewAssetRepo(), nil
}

// List 分页查询验证历史。
func (s *VerificationOpsService) List(ctx context.Context, f repo.VerificationFilter) ([]*repo.VerificationRow, int64, error) {
	a, err := s.assets()
	if err != nil {
		return nil, 0, err
	}
	return a.ListVerifications(ctx, f)
}

// PreviewBatch 返回当前筛选条件下会被复验的站点数与前 20 条样本，不落库、不发请求。
func (s *VerificationOpsService) PreviewBatch(ctx context.Context, q repo.AssetQuery) (*repo.VerificationBatchPreview, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	return a.PreviewVerificationBatch(ctx, q)
}

func normalizeVerificationIDs(ids []int64, limit int) ([]int64, error) {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: site_ids 不能为空", ErrVerificationInput)
	}
	if len(out) > limit {
		return nil, fmt.Errorf("%w: 单次最多处理 %d 个站点", ErrVerificationInput, limit)
	}
	return out, nil
}

// Recheck 强制复验：重置尝试计数与失联状态，让下一轮探测立即重跑。
func (s *VerificationOpsService) Recheck(ctx context.Context, ids []int64, actor, ip string) (*repo.RecheckReport, error) {
	ids, err := normalizeVerificationIDs(ids, repo.VerificationBatchLimit)
	if err != nil {
		return nil, err
	}
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	report, err := a.RecheckSites(ctx, ids)
	if err != nil {
		return nil, err
	}

	if actor == "" {
		actor = "system"
	}
	r := repo.Default()
	for _, item := range report.Items {
		if err := r.LogOperation(ctx, repo.OperationLogInput{
			Username:  actor,
			Action:    "verification_recheck",
			Module:    "asset_governance",
			Target:    item.Host,
			Detail:    fmt.Sprintf("强制复验：state %s -> pending，attempts %d -> 0（site_id=%d）", item.BeforeState, item.BeforeAttempts, item.SiteID),
			IP:        ip,
			UserAgent: "governance/verification-recheck",
		}); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s 审计日志写入失败: %v", item.Host, err))
		}
	}
	return report, nil
}

// LostDeleteItem 是一条被删除的失联站点。
type LostDeleteItem struct {
	SiteID    int64  `json:"site_id"`
	ProjectID int64  `json:"project_id"`
	Host      string `json:"host"`
}

// LostDeleteSkip 是一条被跳过的站点及原因。
type LostDeleteSkip struct {
	SiteID int64  `json:"site_id"`
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// LostDeleteReport 是失联删除的回执。
type LostDeleteReport struct {
	Requested    int              `json:"requested"`
	Deleted      int              `json:"deleted"`
	Skipped      int              `json:"skipped"`
	DeletedItems []LostDeleteItem `json:"deleted_items"`
	SkippedItems []LostDeleteSkip `json:"skipped_items"`
	Warnings     []string         `json:"warnings,omitempty"`
}

type lostProbeResult struct {
	verdict string
	err     error
}

// DeleteLost 逐条复核后删除失联站点。
//
// 复核并发度固定为 4：每个站点内部还会串行探多个入口，再高会把请求拖成
// 「连接打满 + 单条超时」的组合。删除只接受 state=lost 且不在保护期内的站点。
func (s *VerificationOpsService) DeleteLost(ctx context.Context, ids []int64, actor, ip string) (*LostDeleteReport, error) {
	ids, err := normalizeVerificationIDs(ids, repo.VerificationDeleteLimit)
	if err != nil {
		return nil, err
	}
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	candidates, err := a.LostDeleteCandidates(ctx, ids)
	if err != nil {
		return nil, err
	}

	if actor == "" {
		actor = "system"
	}
	report := &LostDeleteReport{
		Requested:    len(ids),
		DeletedItems: []LostDeleteItem{},
		SkippedItems: []LostDeleteSkip{},
	}
	byID := make(map[int64]*repo.LostDeleteCandidate, len(candidates))
	for _, c := range candidates {
		byID[c.ID] = c
	}

	type eligible struct {
		id        int64
		host      string
		projectID int64
		index     int
	}
	eligibleSites := []eligible{}
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{SiteID: id, Reason: "站点不存在"})
			continue
		}
		if c.State != "lost" {
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{
				SiteID: c.ID, Host: c.Host, Reason: "站点不处于失联状态（当前 " + c.State + "）",
			})
			continue
		}
		if c.ProtectedUntil != nil && c.ProtectedUntil.After(time.Now()) {
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{
				SiteID: c.ID, Host: c.Host, Reason: "站点在人工保护期内，截止 " + c.ProtectedUntil.Format(time.RFC3339),
			})
			continue
		}
		eligibleSites = append(eligibleSites, eligible{
			id: c.ID, host: c.Host, projectID: c.ProjectID, index: len(eligibleSites),
		})
	}

	probeResults := make([]lostProbeResult, len(eligibleSites))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, item := range eligibleSites {
		wg.Add(1)
		go func(i int, siteID int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p, perr := s.probes.ProbeSite(ctx, siteID)
			if perr != nil {
				probeResults[i] = lostProbeResult{err: perr}
				return
			}
			probeResults[i] = lostProbeResult{verdict: p.Verdict}
		}(i, item.id)
	}
	wg.Wait()

	r := repo.Default()
	for _, item := range eligibleSites {
		res := probeResults[item.index]
		switch {
		case res.err != nil:
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{
				SiteID: item.id, Host: item.host, Reason: "复核失败，保守跳过: " + res.err.Error(),
			})
			continue
		case res.verdict == "reachable":
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{
				SiteID: item.id, Host: item.host, Reason: "复核可达，已跳过",
			})
			continue
		case res.verdict == "inconclusive":
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{
				SiteID: item.id, Host: item.host, Reason: "复核无法判定（环境噪声），保守跳过",
			})
			continue
		}

		if err := a.DeleteLostSite(ctx, item.id); err != nil {
			if errors.Is(err, repo.ErrNotFound) {
				report.Skipped++
				report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{
					SiteID: item.id, Host: item.host, Reason: "复核后状态已变化，未删除",
				})
				continue
			}
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s 删除失败: %v", item.host, err))
			report.Skipped++
			report.SkippedItems = append(report.SkippedItems, LostDeleteSkip{
				SiteID: item.id, Host: item.host, Reason: "删除失败: " + err.Error(),
			})
			continue
		}

		report.Deleted++
		report.DeletedItems = append(report.DeletedItems, LostDeleteItem{
			SiteID: item.id, ProjectID: item.projectID, Host: item.host,
		})
		if err := r.LogOperation(ctx, repo.OperationLogInput{
			Username:  actor,
			Action:    "lost_delete",
			Module:    "asset_governance",
			Target:    item.host,
			Detail:    fmt.Sprintf("逐条复核不可达后永久删除失联站点（site_id=%d）", item.id),
			IP:        ip,
			UserAgent: "governance/lost-delete",
		}); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s 审计日志写入失败: %v", item.host, err))
		}
	}

	if report.Deleted == 0 && report.Skipped == 0 {
		report.Warnings = append(report.Warnings, "没有可处理的站点")
	}
	return report, nil
}

// VerificationBatchResult 是「按筛选条件批量复验」的回执。
type VerificationBatchResult struct {
	Matched   int64               `json:"matched"`
	Requested int                 `json:"requested"`
	Truncated bool                `json:"truncated"`
	Recheck   *repo.RecheckReport `json:"recheck"`
}

// ExecuteBatch 按资产列表同一套筛选条件取站点并强制复验，单批最多 500 条。
func (s *VerificationOpsService) ExecuteBatch(ctx context.Context, q repo.AssetQuery, actor, ip string) (*VerificationBatchResult, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	preview, err := a.PreviewVerificationBatch(ctx, q)
	if err != nil {
		return nil, err
	}
	ids, err := a.VerificationBatchSiteIDs(ctx, q, repo.VerificationBatchLimit)
	if err != nil {
		return nil, err
	}
	res := &VerificationBatchResult{
		Matched: preview.Total, Requested: len(ids), Truncated: preview.Total > int64(len(ids)),
	}
	if len(ids) == 0 {
		res.Recheck = &repo.RecheckReport{Items: []repo.RecheckItem{}, SkippedItems: []repo.RecheckSkip{}}
		return res, nil
	}
	report, err := s.Recheck(ctx, ids, actor, ip)
	if err != nil {
		return nil, err
	}
	res.Recheck = report
	return res, nil
}

// Stats 返回验证流水的状态与失败原因分布。
func (s *VerificationOpsService) Stats(ctx context.Context, projectID int64) (*repo.VerificationStats, error) {
	a, err := s.assets()
	if err != nil {
		return nil, err
	}
	return a.VerificationStats(ctx, projectID)
}
