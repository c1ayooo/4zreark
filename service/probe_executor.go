package service

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// ProbeExecutor 是治理批次的执行器：领取执行单元 → 探测 → 写回站点状态 → 结案。
//
// 与 task_executor 的分工：那边跑扫描流水线（会产出新证据），这边只做「可达性复核」，
// 不产生新站点、不改标题/指纹，只回答「上次看到的资产现在还在不在」。
type ProbeExecutor struct {
	parallel int
	lease    time.Duration
	stop     chan struct{}
	done     chan struct{}
}

func NewProbeExecutor(parallel int) *ProbeExecutor {
	if parallel <= 0 {
		parallel = 8
	}
	return &ProbeExecutor{
		parallel: parallel,
		lease:    2 * time.Minute,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// RunStats 汇总一次执行。
type RunStats struct {
	Claimed   int `json:"claimed"`
	Reachable int `json:"reachable"`
	Dead      int `json:"dead"`
	Inconcl   int `json:"inconclusive"`
	Skipped   int `json:"skipped"`
	Targets   int `json:"targets_done"`
	RunsDone  int `json:"runs_finished"`
}

func (e *ProbeExecutor) stores() (repo.RunRepo, *repo.AssetRepo, *VerifyService, error) {
	r := repo.Default()
	if r == nil {
		return nil, nil, nil, errors.New("数据层未初始化")
	}
	return r.Runs(), repo.NewAssetRepo(), NewVerifyService(), nil
}

// ProcessOnce 领一批执行单元跑完。runID=0 表示跨批次领取（后台循环用）。
func (e *ProbeExecutor) ProcessOnce(ctx context.Context, runID int64, limit int) (*RunStats, error) {
	runs, assets, verifier, err := e.stores()
	if err != nil {
		return nil, err
	}
	targets, err := runs.ClaimTargets(ctx, runID, e.lease, limit)
	if err != nil {
		return nil, err
	}
	stats := &RunStats{Claimed: len(targets)}
	if len(targets) == 0 {
		return stats, nil
	}

	// capability.probe=false 的目标只做信息收集，不向目标发请求：
	// 直接结案为 skipped，并记录批次以便收尾。
	affectedRuns := map[int64]bool{}
	active := make([]*repo.RunTarget, 0, len(targets))
	for _, t := range targets {
		if v, ok := t.Capability["probe"].(bool); ok && !v {
			if err := runs.CompleteTarget(ctx, t.ID, "skipped"); err != nil {
				log.Printf("[Probe] 执行单元 %d 标记 skipped 失败: %v", t.ID, err)
			}
			stats.Skipped++
			affectedRuns[t.RunID] = true
			continue
		}
		active = append(active, t)
	}
	targets = active

	// 按 (批次, host) 分组：一个站点可能有多个入口，聚合成一次判定，
	// 否则 443 失败、80 成功会来回抖动。
	type group struct {
		runID     int64
		projectID int64
		host      string
		targets   []*repo.RunTarget
	}
	groups := map[string]*group{}
	order := []string{}
	for _, t := range targets {
		key := t.Host
		g, ok := groups[key]
		if !ok {
			g = &group{runID: t.RunID, projectID: t.ProjectID, host: t.Host}
			groups[key] = g
			order = append(order, key)
		}
		g.targets = append(g.targets, t)
	}

	sem := make(chan struct{}, e.parallel)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for _, key := range order {
		g := groups[key]
		wg.Add(1)
		sem <- struct{}{}
		go func(g *group) {
			defer wg.Done()
			defer func() { <-sem }()

			siteID, err := assets.SiteIDByHost(ctx, g.projectID, g.host)
			switch {
			case err == nil:
				report, perr := verifier.ProbeSite(ctx, siteID)
				mu.Lock()
				if perr == nil && report != nil {
					switch report.Verdict {
					case "reachable":
						stats.Reachable++
					case "inconclusive":
						stats.Inconcl++
					default:
						stats.Dead++
					}
				}
				mu.Unlock()
			case errors.Is(err, repo.ErrNotFound):
				// 站点还没归并（计划从种子回落出来的目标）：只探，不写站点
				for _, t := range g.targets {
					res := verifier.ProbeHostPort(ctx, g.host, t.Port)
					mu.Lock()
					switch {
					case res.Reachable():
						stats.Reachable++
					case res.Inconclusive():
						stats.Inconcl++
					default:
						stats.Dead++
					}
					mu.Unlock()
				}
			default:
				log.Printf("[Probe] 查站点失败 %s: %v", g.host, err)
			}

			// 每条执行单元都要落终态，否则租约到期会被重复领取
			for _, t := range g.targets {
				if err := runs.CompleteTarget(ctx, t.ID, "done"); err != nil {
					log.Printf("[Probe] 执行单元 %d 结案失败: %v", t.ID, err)
				}
			}
			mu.Lock()
			stats.Targets += len(g.targets)
			affectedRuns[g.runID] = true
			mu.Unlock()
		}(g)
	}
	wg.Wait()
	finishSettledRuns(ctx, runs, affectedRuns, stats)
	return stats, nil
}

// finishSettledRuns 批次里没有 pending/running 目标时结案（含全量 skipped 的批次）。
func finishSettledRuns(ctx context.Context, runs repo.RunRepo, affectedRuns map[int64]bool, stats *RunStats) {
	for id := range affectedRuns {
		st, err := runs.TargetStats(ctx, id)
		if err != nil {
			continue
		}
		if st["pending"] == 0 && st["running"] == 0 {
			status := "done"
			if st["failed"] > 0 {
				status = "partial"
			}
			if err := runs.FinishRun(ctx, id, status, map[string]any{
				"targets": st,
			}); err == nil {
				stats.RunsDone++
			}
		}
	}
}

// Start 起后台循环：每 5 秒领一批执行单元。并发度靠 parallel 控制。
func (e *ProbeExecutor) Start() {
	go func() {
		defer close(e.done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-e.stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				stats, err := e.ProcessOnce(ctx, 0, 20)
				cancel()
				if err != nil {
					log.Printf("[Probe] 执行失败: %v", err)
					continue
				}
				if stats.Claimed > 0 {
					log.Printf("[Probe] 领取 %d，可达 %d，失联 %d，不确定 %d，结案批次 %d",
						stats.Claimed, stats.Reachable, stats.Dead, stats.Inconcl, stats.RunsDone)
				}
			}
		}
	}()
}

// Stop 停循环并等退出。
func (e *ProbeExecutor) Stop() {
	select {
	case <-e.stop:
		return
	default:
		close(e.stop)
	}
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
	}
}
