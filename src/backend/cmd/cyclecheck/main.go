// 临时验收程序：治理域「周期」骨架（种子 → 计划 → 批次 → 目标 → 租约回收）。
// 直接驱动 repo 与 service，验证 JSON/HTTP 看不到的那部分：领取、续租、过期回收、重试计数。
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var fails int

func check(name string, cond bool, detail string) {
	if cond {
		fmt.Printf("  ✓ %s\n", name)
		return
	}
	fails++
	fmt.Printf("  ✗ %s  → %s\n", name, detail)
}

func main() {
	cfg := config.LoadConfig("config/config.yaml")
	if cfg == nil || cfg.Postgres.Host == "" {
		fmt.Println("读取配置失败")
		os.Exit(1)
	}
	if _, err := repo.Open(context.Background(), &cfg.Postgres); err != nil {
		fmt.Println("连接 PG 失败:", err)
		os.Exit(1)
	}
	r := repo.Default()
	seeds, runs := r.Seeds(), r.Runs()
	cycles := service.NewCycleService()
	ctx := context.Background()

	// 借一个已有项目做宿主（种子必须挂在项目上）
	var projectID int64
	if err := r.Pool().QueryRow(ctx, `select id from projects order by id limit 1`).Scan(&projectID); err != nil {
		fmt.Println("没有可用项目:", err)
		os.Exit(1)
	}
	tag := primitive.NewObjectID().Hex()[:8]
	domain := "demo.org" // 已有站点里大量 *.demo.org
	fmt.Printf("project_id=%d 探针标记=%s\n\n", projectID, tag)

	// --- 1. 种子 ---
	fmt.Println("[1] 种子")
	seed := &repo.Seed{ProjectID: projectID, Kind: "domain", Value: domain, Enabled: true,
		Capability: map[string]any{"probe": tag}}
	check("建种子", seeds.CreateSeed(ctx, seed) == nil, "失败")
	check("重复种子被拒", seeds.CreateSeed(ctx, &repo.Seed{ProjectID: projectID, Kind: "domain",
		Value: domain, Enabled: true}) != nil, "应当因唯一约束失败")
	list, err := seeds.ListSeeds(ctx, projectID)
	check("种子可列出", err == nil && len(list) > 0, fmt.Sprintf("len=%d err=%v", len(list), err))

	// --- 2. 计划 ---
	fmt.Println("[2] 计划")
	plan := &repo.Plan{SeedID: seed.ID, IntervalHours: 24, Enabled: true}
	check("建计划", seeds.CreatePlan(ctx, plan) == nil, "失败")
	got, err := seeds.GetPlan(ctx, plan.ID)
	check("计划带出种子信息", err == nil && got.SeedValue == domain && got.ProjectID == projectID,
		fmt.Sprintf("%+v err=%v", got, err))
	check("新计划立即到期", got.NextRunAt != nil && !got.NextRunAt.After(time.Now()),
		fmt.Sprintf("next_run_at=%v", got.NextRunAt))
	due, err := seeds.DuePlans(ctx, 50)
	found := false
	for _, p := range due {
		if p.ID == plan.ID {
			found = true
		}
	}
	check("到期计划里能查到", err == nil && found, fmt.Sprintf("due=%d err=%v", len(due), err))

	// --- 3. 推进：建批次 + 展开目标 ---
	fmt.Println("[3] Tick 推进")
	res, err := cycles.Tick(ctx, 20)
	check("Tick 无错误", err == nil, fmt.Sprintf("%v", err))
	if res != nil {
		fmt.Printf("    due=%d created=%d existing=%d targets=%d advanced=%d empty=%d reaped=%d\n",
			res.DuePlans, res.RunsCreated, res.RunsExisting, res.TargetsAdded,
			res.PlansAdvanced, res.EmptySeeds, res.Reaped)
	}
	runList, err := runs.ListRuns(ctx, projectID, 20)
	check("批次已生成", err == nil && len(runList) > 0, fmt.Sprintf("len=%d err=%v", len(runList), err))
	if len(runList) == 0 {
		os.Exit(1)
	}
	run := runList[0]
	stats, _ := runs.TargetStats(ctx, run.ID)
	check("批次有执行单元", stats["pending"] > 0, fmt.Sprintf("stats=%v", stats))
	fmt.Printf("    run=%d cycle_start=%s targets(pending)=%d\n",
		run.ID, run.CycleStart.Format(time.RFC3339), stats["pending"])

	// 幂等：再 Tick 一次不应该新建批次
	res2, _ := cycles.Tick(ctx, 20)
	check("重复 Tick 不新建批次", res2 != nil && res2.RunsCreated == 0,
		fmt.Sprintf("created=%d", res2.RunsCreated))
	after, _ := runs.ListRuns(ctx, projectID, 20)
	check("批次总数没变", len(after) == len(runList), fmt.Sprintf("%d -> %d", len(runList), len(after)))
	check("计划游标已推进", func() bool {
		p, err := seeds.GetPlan(ctx, plan.ID)
		return err == nil && p.NextRunAt != nil && p.NextRunAt.After(time.Now())
	}(), "next_run_at 未推进")

	// --- 4. 领取 / 租约 / 回收 ---
	fmt.Println("[4] 领取、租约、回收")
	claimed, err := runs.ClaimTargets(ctx, run.ID, 600*time.Millisecond, 3)
	check("领到 3 个执行单元", err == nil && len(claimed) == 3, fmt.Sprintf("len=%d err=%v", len(claimed), err))
	if len(claimed) >= 1 {
		check("领取后 attempts=1", claimed[0].Attempts == 1, fmt.Sprintf("%d", claimed[0].Attempts))
		check("领取后状态 running", claimed[0].State == "running", claimed[0].State)
	}
	// 租约内再领：应拿到另外的（不同 id），不会重复领同一个
	again, _ := runs.ClaimTargets(ctx, run.ID, 600*time.Millisecond, 3)
	dup := false
	for _, a := range again {
		for _, c := range claimed {
			if a.ID == c.ID {
				dup = true
			}
		}
	}
	check("租约内不会重复领取同一条", !dup, "出现重复 id")

	time.Sleep(800 * time.Millisecond)
	reaped, err := runs.ReapTargets(ctx)
	check("过期租约被回收", err == nil && reaped >= 6, fmt.Sprintf("reaped=%d err=%v", reaped, err))
	st, _ := runs.TargetStats(ctx, run.ID)
	check("回收到 pending", st["running"] == 0, fmt.Sprintf("stats=%v", st))

	reclaimed, _ := runs.ClaimTargets(ctx, run.ID, time.Minute, 3)
	check("回收后能重新领取", len(reclaimed) == 3, fmt.Sprintf("len=%d", len(reclaimed)))
	if len(reclaimed) >= 1 {
		check("重领后 attempts 累加", reclaimed[0].Attempts == 2, fmt.Sprintf("%d", reclaimed[0].Attempts))
		check("完成执行单元", runs.CompleteTarget(ctx, reclaimed[0].ID, "done") == nil, "失败")
	}

	// --- 5. 收尾 ---
	fmt.Println("[5] 收尾")
	check("FinishRun", runs.FinishRun(ctx, run.ID, "partial", map[string]any{"probe": tag}) == nil, "失败")
	fin, err := runs.GetRun(ctx, run.ID)
	check("批次状态已落库", err == nil && fin.Status == "partial" && fin.EndedAt != nil,
		fmt.Sprintf("%+v", fin))

	check("删计划（级联批次）", seeds.DeletePlan(ctx, plan.ID) == nil, "失败")
	_, err = runs.GetRun(ctx, run.ID)
	check("批次随之删除", err != nil, "批次仍在")
	check("删种子", seeds.DeleteSeed(ctx, seed.ID) == nil, "失败")

	fmt.Println()
	if fails > 0 {
		fmt.Printf("失败 %d 项\n", fails)
		os.Exit(1)
	}
	fmt.Println("全部通过")
}
