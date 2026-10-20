package service

import (
	"context"
	"errors"
	"log"
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
}

func NewCycleService() *CycleService {
	return &CycleService{stop: make(chan struct{}), done: make(chan struct{})}
}

// TickResult 汇总一次推进的结果，接口与日志都用它。
type TickResult struct {
	DuePlans      int   `json:"due_plans"`
	RunsCreated   int   `json:"runs_created"`
	RunsExisting  int   `json:"runs_existing"`
	TargetsAdded  int64 `json:"targets_added"`
	PlansAdvanced int   `json:"plans_advanced"`
	EmptySeeds    int   `json:"empty_seeds"`
	Reaped        int64 `json:"reaped"`
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

		run, created, err := runs.CreateRun(ctx, repo.CreateRunInput{
			PlanID:     plan.ID,
			ProjectID:  plan.ProjectID,
			CycleStart: cycleStart,
			Budget:     plan.Budget,
		})
		if err != nil {
			log.Printf("[Cycle] 计划 %d 建批次失败: %v", plan.ID, err)
			continue
		}
		if created {
			res.RunsCreated++
		} else {
			res.RunsExisting++
		}

		// 已存在的批次只有在「一条目标都没有」时才补展开：
		// 上一轮可能在建完批次、展开前失败，这里负责补上，不留空批次。
		needExpand := created
		if !needExpand {
			stats, err := runs.TargetStats(ctx, run.ID)
			if err == nil && len(stats) == 0 {
				needExpand = true
			}
		}
		if needExpand {
			targets, err := s.expand(ctx, plan)
			if err != nil {
				log.Printf("[Cycle] 计划 %d 展开失败: %v", plan.ID, err)
				continue
			}
			if len(targets) == 0 {
				res.EmptySeeds++
			}
			n, err := runs.AddTargets(ctx, run.ID, targets)
			if err != nil {
				log.Printf("[Cycle] 计划 %d 写执行单元失败: %v", plan.ID, err)
				continue
			}
			res.TargetsAdded += n
		}

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
	return res, nil
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
		targets, err := s.expand(ctx, plan)
		if err != nil {
			return run, created, err
		}
		if _, err := runs.AddTargets(ctx, run.ID, targets); err != nil {
			return run, created, err
		}
	}
	return run, created, nil
}

// expand 把一个种子展开成执行单元。
// domain 类型取该项目下已归并站点的全部入口（每个 scheme+port 一条），
// 没有任何站点时回落到种子本身 :443 —— 第一次采集靠手工导入，计划负责之后的回归。
func (s *CycleService) expand(ctx context.Context, plan *repo.Plan) ([]repo.TargetInput, error) {
	if plan.SeedKind != "domain" {
		// cidr / company / repo / app / dict 的展开要真实采集器，G3/G4 再接
		return nil, nil
	}
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	targets, err := r.AssetTargetsForDomain(ctx, plan.ProjectID, plan.SeedValue, 2000)
	if err != nil {
		return nil, err
	}
	if len(targets) > 0 {
		return targets, nil
	}
	return []repo.TargetInput{{Host: plan.SeedValue, Port: 443}}, nil
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
