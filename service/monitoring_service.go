package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
)

var ErrMonitoringInput = errors.New("监控配置参数错误")

// MonitoringService 负责监控预设与计划批量操作。
type MonitoringService struct{}

func NewMonitoringService() *MonitoringService { return &MonitoringService{} }

func (s *MonitoringService) ops() (*repo.SeedOpsRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().SeedOps(), nil
}

func normalizePresetInput(in repo.MonitoringPresetInput) (repo.MonitoringPresetInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > 120 {
		return in, fmt.Errorf("%w: 预设名必填且不超过 120 字", ErrMonitoringInput)
	}
	if in.IntervalHours < 1 || in.IntervalHours > 720 {
		return in, fmt.Errorf("%w: interval_hours 需在 1..720", ErrMonitoringInput)
	}
	if in.Budget == nil {
		in.Budget = map[string]any{}
	}
	return in, nil
}

func (s *MonitoringService) ListPresets(ctx context.Context) ([]*repo.MonitoringPreset, error) {
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	return ops.ListPresets(ctx)
}

func (s *MonitoringService) DefaultPreset(ctx context.Context) (*repo.MonitoringPreset, error) {
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	return ops.DefaultPreset(ctx)
}

func (s *MonitoringService) CreatePreset(ctx context.Context, in repo.MonitoringPresetInput, actor, ip string) (*repo.MonitoringPreset, error) {
	in, err := normalizePresetInput(in)
	if err != nil {
		return nil, err
	}
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	p, err := ops.CreatePreset(ctx, in)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, actor, ip, "monitoring_preset_create", p.Name, "创建监控预设")
	return p, nil
}

func (s *MonitoringService) UpdatePreset(ctx context.Context, id int64, in repo.MonitoringPresetInput, actor, ip string) (*repo.MonitoringPreset, error) {
	in, err := normalizePresetInput(in)
	if err != nil {
		return nil, err
	}
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	p, err := ops.UpdatePreset(ctx, id, in)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, actor, ip, "monitoring_preset_update", p.Name, "更新监控预设")
	return p, nil
}

func (s *MonitoringService) DeletePreset(ctx context.Context, id int64, actor, ip string) error {
	ops, err := s.ops()
	if err != nil {
		return err
	}
	if err := ops.DeletePreset(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, ip, "monitoring_preset_delete", fmt.Sprintf("id=%d", id), "删除监控预设")
	return nil
}

func (s *MonitoringService) audit(ctx context.Context, actor, ip, action, target, detail string) {
	if repo.Default() == nil {
		return
	}
	if actor == "" {
		actor = "system"
	}
	if err := repo.Default().LogOperation(ctx, repo.OperationLogInput{
		Username: actor, Action: action, Module: "monitoring", Target: target,
		Detail: detail, IP: ip, UserAgent: "governance/monitoring",
	}); err != nil {
		log.Printf("[Monitoring] 审计写入失败: %v", err)
	}
}

// PlanBulkRequest 是计划批量操作的入参。
type PlanBulkRequest struct {
	PlanIDs       []int64 `json:"plan_ids"`
	ProjectID     int64   `json:"project_id"`
	Enabled       *bool   `json:"enabled"`
	IntervalHours *int    `json:"interval_hours"`
}

func (r *PlanBulkRequest) validate() error {
	if len(r.PlanIDs) == 0 && r.ProjectID <= 0 {
		return fmt.Errorf("%w: plan_ids 与 project_id 至少提供一个", ErrMonitoringInput)
	}
	if r.Enabled == nil && r.IntervalHours == nil {
		return fmt.Errorf("%w: enabled 与 interval_hours 至少提供一个", ErrMonitoringInput)
	}
	if r.IntervalHours != nil && (*r.IntervalHours < 1 || *r.IntervalHours > 720) {
		return fmt.Errorf("%w: interval_hours 需在 1..720", ErrMonitoringInput)
	}
	return nil
}

func normalizePlanIDs(ids []int64) []int64 {
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
	return out
}

// PlanBulkPreview 是批量操作预览。
type PlanBulkPreview struct {
	Total  int          `json:"total"`
	Sample []*repo.Plan `json:"sample"`
}

func (s *MonitoringService) PreviewBulk(ctx context.Context, req PlanBulkRequest) (*PlanBulkPreview, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	plans, err := ops.ListPlansForBulk(ctx, repo.PlanBulkFilter{
		PlanIDs: normalizePlanIDs(req.PlanIDs), ProjectID: req.ProjectID,
	})
	if err != nil {
		return nil, err
	}
	sample := plans
	if len(sample) > 20 {
		sample = sample[:20]
	}
	return &PlanBulkPreview{Total: len(plans), Sample: sample}, nil
}

// PlanBulkResult 是批量操作回执。
type PlanBulkResult struct {
	Requested     int   `json:"requested"`
	Updated       int64 `json:"updated"`
	Enabled       *bool `json:"enabled,omitempty"`
	IntervalHours *int  `json:"interval_hours,omitempty"`
}

func (s *MonitoringService) ApplyBulk(ctx context.Context, req PlanBulkRequest, actor, ip string) (*PlanBulkResult, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	ops, err := s.ops()
	if err != nil {
		return nil, err
	}
	planIDs := normalizePlanIDs(req.PlanIDs)
	plans, err := ops.ListPlansForBulk(ctx, repo.PlanBulkFilter{PlanIDs: planIDs, ProjectID: req.ProjectID})
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(plans))
	for _, p := range plans {
		ids = append(ids, p.ID)
	}
	updated, err := ops.BulkUpdatePlans(ctx, ids, req.Enabled, req.IntervalHours)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, actor, ip, "monitoring_bulk_update", fmt.Sprintf("%d 个计划", len(ids)),
		fmt.Sprintf("批量更新 enabled=%v interval=%v，实际更新 %d 条", req.Enabled, req.IntervalHours, updated))
	return &PlanBulkResult{
		Requested: len(ids), Updated: updated,
		Enabled: req.Enabled, IntervalHours: req.IntervalHours,
	}, nil
}
