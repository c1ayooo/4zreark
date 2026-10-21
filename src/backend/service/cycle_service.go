package service

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// CycleService 负责治理域的「周期」：计划到期 → 建批次 → 展开执行单元。
//
// G1 只做骨架：批次建出来、目标展开好、租约与回收能跑通。
// 真正发 HTTP 探测在 G2（会写回 sites 的连通性与 verifications），不在这里。
type CycleService struct {
	stop chan struct{}
	done chan struct{}
	// expandDomainHook 仅供测试替换域名展开；nil 时走真实仓储。
	expandDomainHook func(ctx context.Context, projectID int64, domain string, max int) ([]repo.TargetInput, []string, error)
}

func NewCycleService() *CycleService {
	return &CycleService{stop: make(chan struct{}), done: make(chan struct{})}
}

// TickResult 汇总一次推进的结果，接口与日志都用它。
type TickResult struct {
	DuePlans      int   `json:"due_plans"`
	ChangePlans   int   `json:"change_plans"`
	RunsCreated   int   `json:"runs_created"`
	RunsExisting  int   `json:"runs_existing"`
	TargetsAdded  int64 `json:"targets_added"`
	PlansAdvanced int   `json:"plans_advanced"`
	EmptySeeds    int   `json:"empty_seeds"`
	Reaped        int64 `json:"reaped"`
	BudgetLimited int   `json:"budget_limited"`
}

func (s *CycleService) stores() (repo.SeedRepo, repo.RunRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, nil, errors.New("数据层未初始化")
	}
	return r.Seeds(), r.Runs(), nil
}

// Tick 推进一轮：回收过期租约、把到期的计划各起一个批次、展开执行单元。
// 幂等：同一个计划的同一个 cycle_start 只有一个批次，重复调用只会补展开。
func (s *CycleService) Tick(ctx context.Context, limit int) (*TickResult, error) {
	seeds, runs, err := s.stores()
	if err != nil {
		return nil, err
	}
	res := &TickResult{}

	// 先回收：租约过期的执行单元回到 pending，超过 3 次的判 failed
	if n, err := runs.ReapTargets(ctx); err == nil {
		res.Reaped = n
	} else {
		log.Printf("[Cycle] 回收过期执行单元失败: %v", err)
	}

	plans, err := seeds.DuePlans(ctx, limit)
	if err != nil {
		return res, err
	}
	res.DuePlans = len(plans)

	for _, plan := range plans {
		// cycle_start 用计划自己的游标，保证并发/重试时幂等键一致
		cycleStart := time.Now()
		if plan.NextRunAt != nil {
			cycleStart = *plan.NextRunAt
		}

		rr, err := s.runPlan(ctx, runs, plan, cycleStart)
		if err != nil {
			log.Printf("[Cycle] 计划 %d 执行失败: %v", plan.ID, err)
			continue
		}
		res.merge(rr)

		// 游标按「本周期 + 间隔」推进，避免 now()+间隔 造成的节奏漂移
		next := cycleStart.Add(time.Duration(plan.IntervalHours) * time.Hour)
		if next.Before(time.Now()) {
			next = time.Now().Add(time.Duration(plan.IntervalHours) * time.Hour)
		}
		if err := seeds.MarkPlanRan(ctx, plan.ID, next); err != nil {
			log.Printf("[Cycle] 计划 %d 推进游标失败: %v", plan.ID, err)
			continue
		}
		res.PlansAdvanced++
	}

	// 资产变化触发的计划：与到期计划共用展开逻辑，只是 cycle_start
	// 取「当前分钟」做幂等键——同一分钟内多个事件只产生一个批次。
	changePlans, err := seeds.ChangeTriggeredPlans(ctx, limit)
	if err != nil {
		log.Printf("[Cycle] 查询变更触发计划失败: %v", err)
		return res, nil
	}
	res.ChangePlans = len(changePlans)
	for _, plan := range changePlans {
		cycleStart := time.Now().Truncate(time.Minute)
		rr, err := s.runPlan(ctx, runs, plan, cycleStart)
		if err != nil {
			log.Printf("[Cycle] 变更触发计划 %d 执行失败: %v", plan.ID, err)
			continue
		}
		res.merge(rr)
		// 只推进 last_run_at：变更触发是额外跑一次，不打乱固定周期游标。
		if err := seeds.MarkPlanChangeRan(ctx, plan.ID); err != nil {
			log.Printf("[Cycle] 计划 %d 更新变更游标失败: %v", plan.ID, err)
		}
	}
	return res, nil
}

// planRunResult 是一次计划执行对 TickResult 的增量。
type planRunResult struct {
	Created       bool
	Empty         bool
	BudgetLimited bool
	TargetsAdded  int64
}

func (r *TickResult) merge(x planRunResult) {
	if x.Created {
		r.RunsCreated++
	} else {
		r.RunsExisting++
	}
	if x.Empty {
		r.EmptySeeds++
	}
	if x.BudgetLimited {
		r.BudgetLimited++
	}
	r.TargetsAdded += x.TargetsAdded
}

// runPlan 建批次（幂等）并在需要时展开目标。到期计划与变更触发计划共用。
func (s *CycleService) runPlan(ctx context.Context, runs repo.RunRepo, plan *repo.Plan, cycleStart time.Time) (planRunResult, error) {
	var out planRunResult
	run, created, err := runs.CreateRun(ctx, repo.CreateRunInput{
		PlanID:     plan.ID,
		ProjectID:  plan.ProjectID,
		CycleStart: cycleStart,
		Budget:     plan.Budget,
	})
	if err != nil {
		return out, err
	}
	out.Created = created

	// 已存在的批次只有在「一条目标都没有」时才补展开：
	// 上一轮可能在建完批次、展开前失败，这里负责补上，不留空批次。
	needExpand := created
	if !needExpand {
		stats, serr := runs.TargetStats(ctx, run.ID)
		if serr == nil && len(stats) == 0 {
			needExpand = true
		}
	}
	if !needExpand {
		return out, nil
	}

	expanded, err := s.expand(ctx, plan)
	if err != nil {
		return out, err
	}
	raw := expanded.Targets
	targets := s.applyDailyBudget(ctx, runs, plan.ProjectID, plan.Budget, raw)
	if len(raw) == 0 {
		out.Empty = true
		if err := runs.MergeRunStats(ctx, run.ID, map[string]any{
			"empty_reason": expanded.EmptyReason,
			"targets":      0,
		}); err != nil {
			log.Printf("[Cycle] 计划 %d 写空展开原因失败: %v", plan.ID, err)
		}
	} else if len(targets) < len(raw) {
		out.BudgetLimited = true
	}
	n, err := runs.AddTargets(ctx, run.ID, targets)
	if err != nil {
		return out, err
	}
	out.TargetsAdded = n
	return out, nil
}

// TriggerPlan 手动触发一个计划，不等它到期。同一分钟内重复触发只会有一个批次。
func (s *CycleService) TriggerPlan(ctx context.Context, planID int64) (*repo.Run, bool, error) {
	seeds, runs, err := s.stores()
	if err != nil {
		return nil, false, err
	}
	plan, err := seeds.GetPlan(ctx, planID)
	if err != nil {
		return nil, false, err
	}

	cycleStart := time.Now().Truncate(time.Minute)
	run, created, err := runs.CreateRun(ctx, repo.CreateRunInput{
		PlanID:     plan.ID,
		ProjectID:  plan.ProjectID,
		CycleStart: cycleStart,
		Budget:     plan.Budget,
	})
	if err != nil {
		return nil, false, err
	}
	if created {
		expanded, err := s.expand(ctx, plan)
		if err != nil {
			return run, created, err
		}
		targets := s.applyDailyBudget(ctx, runs, plan.ProjectID, plan.Budget, expanded.Targets)
		if len(expanded.Targets) == 0 {
			if err := runs.MergeRunStats(ctx, run.ID, map[string]any{
				"empty_reason": expanded.EmptyReason,
				"targets":      0,
			}); err != nil {
				log.Printf("[Cycle] 计划 %d 写空展开原因失败: %v", plan.ID, err)
			}
		}
		if _, err := runs.AddTargets(ctx, run.ID, targets); err != nil {
			return run, created, err
		}
	}
	return run, created, nil
}

// applyDailyBudget 按计划的 budget.daily_targets 截断本轮目标。
// 预算按项目/自然日统计（所有计划共享），耗尽后本轮不再新增目标。
func (s *CycleService) applyDailyBudget(ctx context.Context, runs repo.RunRepo, projectID int64, budget map[string]any, targets []repo.TargetInput) []repo.TargetInput {
	limit := budgetDailyTargets(budget)
	if limit <= 0 || len(targets) == 0 {
		return targets
	}
	used, err := runs.TargetsAddedToday(ctx, projectID)
	if err != nil {
		log.Printf("[Cycle] 项目 %d 读取当日预算用量失败: %v", projectID, err)
		return targets
	}
	remaining := limit - int(used)
	if remaining <= 0 {
		log.Printf("[Cycle] 项目 %d 当日预算已用完（%d/%d），本轮跳过 %d 个目标", projectID, used, limit, len(targets))
		return nil
	}
	if len(targets) > remaining {
		log.Printf("[Cycle] 项目 %d 当日预算剩余 %d，截断 %d 个目标", projectID, remaining, len(targets)-remaining)
		return targets[:remaining]
	}
	return targets
}

// budgetDailyTargets 读取 budget JSON 里的每日目标上限。
// 支持 daily_targets / max_targets_per_day / daily 三种键（数字或数字字符串）。
func budgetDailyTargets(budget map[string]any) int {
	for _, key := range []string{"daily_targets", "max_targets_per_day", "daily"} {
		v, ok := budget[key]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case int64:
			return int(n)
		case string:
			if x, err := strconv.Atoi(n); err == nil {
				return x
			}
		}
	}
	return 0
}

// expand 加载种子并调用统一展开器，保证 preview 与实际批次走同一套规则。
func (s *CycleService) expand(ctx context.Context, plan *repo.Plan) (*SeedExpandResult, error) {
	seeds, _, err := s.stores()
	if err != nil {
		return nil, err
	}
	seed, err := seeds.GetSeed(ctx, plan.SeedID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return &SeedExpandResult{
				Kind: plan.SeedKind, Source: plan.SeedKind,
				Targets: []repo.TargetInput{}, Warnings: []string{"种子不存在"},
				EmptyReason: "seed_missing",
			}, nil
		}
		return nil, err
	}
	live, _ := seed.Capability["live"].(bool)
	return s.ExpandSeed(ctx, seed, live, SeedMaxTargets, SeedMaxTargets)
}

// Start 起后台循环：每 60 秒回收一次过期租约、推进一次到期计划。
func (s *CycleService) Start() {
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		// 启动先跑一轮，避免重启后第一批计划要等满一个周期
		s.runOnce()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.runOnce()
			}
		}
	}()
}

func (s *CycleService) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := s.Tick(ctx, 20)
	if err != nil {
		log.Printf("[Cycle] 推进失败: %v", err)
		return
	}
	if res.RunsCreated > 0 || res.Reaped > 0 {
		log.Printf("[Cycle] 到期计划 %d，新建批次 %d，展开执行单元 %d，回收 %d",
			res.DuePlans, res.RunsCreated, res.TargetsAdded, res.Reaped)
	}
}

// Stop 停后台循环并等它退出。
func (s *CycleService) Stop() {
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
	}
}
