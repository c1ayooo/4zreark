package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
)

// GovernanceService 是「种子 → 计划 → 批次 → 执行单元」的服务层入口。
// 现有 HTTP handler 直接调 repo，这里补齐服务层给 MCP 复用，避免 MCP 里出现 SQL/仓储细节。
type GovernanceService struct {
	cycles    *CycleService
	probes    *ProbeExecutor
	relations *RelationService
	replay    *ReplayService
}

func NewGovernanceService() *GovernanceService {
	return &GovernanceService{
		cycles:    NewCycleService(),
		probes:    NewProbeExecutor(8),
		relations: NewRelationService(),
		replay:    NewReplayService(),
	}
}

func (s *GovernanceService) stores() (repo.SeedRepo, repo.RunRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, nil, errors.New("数据层未初始化")
	}
	return r.Seeds(), r.Runs(), nil
}

var seedKinds = map[string]bool{
	"domain": true, "cidr": true, "company": true, "cert": true, "repo": true, "app": true, "dict": true,
}

func (s *GovernanceService) ListSeeds(ctx context.Context, projectID int64) ([]*repo.Seed, error) {
	seeds, _, err := s.stores()
	if err != nil {
		return nil, err
	}
	return seeds.ListSeeds(ctx, projectID)
}

func (s *GovernanceService) GetSeed(ctx context.Context, id int64) (*repo.Seed, error) {
	seeds, _, err := s.stores()
	if err != nil {
		return nil, err
	}
	return seeds.GetSeed(ctx, id)
}

func (s *GovernanceService) CreateSeed(ctx context.Context, projectID int64, kind, value string, capability map[string]any) (*repo.Seed, error) {
	kind = strings.TrimSpace(kind)
	value = strings.TrimSpace(value)
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	if !seedKinds[kind] {
		return nil, errors.New("kind 只支持 domain / cidr / company / cert / repo / app / dict")
	}
	if value == "" {
		return nil, errors.New("种子值不能为空")
	}
	if _, err := repo.NewAssetRepo().GetProject(ctx, projectID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("项目不存在")
		}
		return nil, err
	}
	seeds, _, err := s.stores()
	if err != nil {
		return nil, err
	}
	seed := &repo.Seed{
		ProjectID: projectID, Kind: kind, Value: value,
		Capability: capability, Enabled: true,
	}
	if err := seeds.CreateSeed(ctx, seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func (s *GovernanceService) DeleteSeed(ctx context.Context, id int64) error {
	seeds, _, err := s.stores()
	if err != nil {
		return err
	}
	if _, err := seeds.GetSeed(ctx, id); err != nil {
		return err
	}
	return seeds.DeleteSeed(ctx, id)
}

func (s *GovernanceService) ListPlans(ctx context.Context, projectID int64) ([]*repo.Plan, error) {
	seeds, _, err := s.stores()
	if err != nil {
		return nil, err
	}
	return seeds.ListPlans(ctx, projectID)
}

func (s *GovernanceService) GetPlan(ctx context.Context, id int64) (*repo.Plan, error) {
	seeds, _, err := s.stores()
	if err != nil {
		return nil, err
	}
	return seeds.GetPlan(ctx, id)
}

func (s *GovernanceService) CreatePlan(ctx context.Context, seedID int64, intervalHours int, budget map[string]any, triggerMode string, cooldownMinutes int) (*repo.Plan, error) {
	if seedID <= 0 {
		return nil, errors.New("seed_id 必填")
	}
	if intervalHours == 0 {
		intervalHours = 24
	}
	if intervalHours < 1 || intervalHours > 720 {
		return nil, errors.New("interval_hours 需在 1..720")
	}
	if triggerMode == "" {
		triggerMode = repo.PlanTriggerInterval
	}
	switch triggerMode {
	case repo.PlanTriggerInterval, repo.PlanTriggerOnChange, repo.PlanTriggerBoth:
	default:
		return nil, errors.New("trigger_mode 只支持 interval / on_change / both")
	}
	if cooldownMinutes == 0 {
		cooldownMinutes = 10
	}
	if cooldownMinutes < 1 || cooldownMinutes > 1440 {
		return nil, errors.New("change_cooldown_minutes 需在 1..1440")
	}
	seeds, _, err := s.stores()
	if err != nil {
		return nil, err
	}
	if _, err := seeds.GetSeed(ctx, seedID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("种子不存在")
		}
		return nil, err
	}
	plan := &repo.Plan{
		SeedID: seedID, IntervalHours: intervalHours, Budget: budget, Enabled: true,
		TriggerMode: triggerMode, ChangeCooldownMinutes: cooldownMinutes,
	}
	if err := seeds.CreatePlan(ctx, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (s *GovernanceService) UpdatePlan(ctx context.Context, id int64, enabled *bool, intervalHours *int, triggerMode *string, cooldownMinutes *int) error {
	if intervalHours != nil && (*intervalHours < 1 || *intervalHours > 720) {
		return errors.New("interval_hours 需在 1..720")
	}
	seeds, _, err := s.stores()
	if err != nil {
		return err
	}
	return seeds.UpdatePlan(ctx, id, enabled, intervalHours, triggerMode, cooldownMinutes)
}

func (s *GovernanceService) DeletePlan(ctx context.Context, id int64) error {
	seeds, _, err := s.stores()
	if err != nil {
		return err
	}
	return seeds.DeletePlan(ctx, id)
}

func (s *GovernanceService) TriggerPlan(ctx context.Context, id int64) (*repo.Run, bool, error) {
	return s.cycles.TriggerPlan(ctx, id)
}

func (s *GovernanceService) ListRuns(ctx context.Context, projectID int64, limit int) ([]*repo.Run, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	_, runs, err := s.stores()
	if err != nil {
		return nil, err
	}
	return runs.ListRuns(ctx, projectID, limit)
}

func (s *GovernanceService) GetRun(ctx context.Context, id int64) (*repo.Run, map[string]int, error) {
	_, runs, err := s.stores()
	if err != nil {
		return nil, nil, err
	}
	run, err := runs.GetRun(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	stats, err := runs.TargetStats(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return run, stats, nil
}

func (s *GovernanceService) ListTargets(ctx context.Context, runID int64, state string, limit int) ([]*repo.RunTarget, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	_, runs, err := s.stores()
	if err != nil {
		return nil, err
	}
	return runs.ListTargets(ctx, runID, state, limit)
}

func (s *GovernanceService) ExecuteRun(ctx context.Context, runID int64, limit int) (*RunStats, error) {
	if runID <= 0 {
		return nil, errors.New("run_id 必填")
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	return s.probes.ProcessOnce(ctx, runID, limit)
}

func (s *GovernanceService) PreviewSeed(ctx context.Context, req SeedPreviewRequest) (*SeedExpandResult, error) {
	return s.cycles.PreviewSeed(ctx, req)
}

func (s *GovernanceService) RebuildRelations(ctx context.Context, projectID int64) (map[string]int64, error) {
	if projectID < 0 {
		return nil, fmt.Errorf("项目 ID 非法")
	}
	return s.relations.Rebuild(ctx, projectID)
}

func (s *GovernanceService) ReplayResults(ctx context.Context, projectID int64, limit int) (*ReplayStats, error) {
	if projectID < 0 {
		return nil, fmt.Errorf("项目 ID 非法")
	}
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	return s.replay.Replay(ctx, projectID, limit)
}

func (s *GovernanceService) RelationGraph(ctx context.Context, projectID int64, typ string, limit int) (any, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	return s.relations.Graph(ctx, projectID, typ, limit)
}

func (s *GovernanceService) RelationStatus(ctx context.Context, projectID int64) (any, error) {
	return s.relations.Status(ctx, projectID)
}
