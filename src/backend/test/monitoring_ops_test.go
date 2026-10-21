package test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 监控预设 CRUD、计划批量操作、情报富化总览。
func TestMonitoringPresetsAndBulkOps(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	actor := fmt.Sprintf("mon-%d", time.Now().UnixNano())
	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("mon%d", time.Now().UnixNano()),
		Name: "monitoring ops test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	seed := &repo.Seed{ProjectID: project.ID, Kind: "domain", Value: "mon.example", Enabled: true}
	if err := r.Seeds().CreateSeed(ctx, seed); err != nil {
		t.Fatalf("创建种子失败: %v", err)
	}
	plan1 := &repo.Plan{SeedID: seed.ID, IntervalHours: 24, Budget: map[string]any{}, Enabled: true}
	plan2 := &repo.Plan{SeedID: seed.ID, IntervalHours: 24, Budget: map[string]any{}, Enabled: true}
	if err := r.Seeds().CreatePlan(ctx, plan1); err != nil {
		t.Fatal(err)
	}
	if err := r.Seeds().CreatePlan(ctx, plan2); err != nil {
		t.Fatal(err)
	}

	presetIDs := []int64{}
	t.Cleanup(func() {
		for _, id := range presetIDs {
			_, _ = r.Pool().Exec(context.Background(), `DELETE FROM monitoring_presets WHERE id = $1`, id)
		}
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM operation_logs WHERE username = $1`, actor)
	})

	svc := service.NewMonitoringService()
	nameA := actor + "-a"
	nameB := actor + "-b"
	a, err := svc.CreatePreset(ctx, repo.MonitoringPresetInput{
		Name: nameA, IntervalHours: 12, IsDefault: true, Budget: map[string]any{"daily_targets": 5},
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("创建预设失败: %v", err)
	}
	presetIDs = append(presetIDs, a.ID)
	if !a.IsDefault || a.IntervalHours != 12 {
		t.Fatalf("预设 A 不符: %+v", a)
	}
	if got, err := svc.DefaultPreset(ctx); err != nil || got == nil || got.ID != a.ID {
		t.Fatalf("默认预设应为 A: %+v err=%v", got, err)
	}

	b, err := svc.CreatePreset(ctx, repo.MonitoringPresetInput{
		Name: nameB, IntervalHours: 24, IsDefault: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("创建预设 B 失败: %v", err)
	}
	presetIDs = append(presetIDs, b.ID)
	if got, _ := svc.DefaultPreset(ctx); got == nil || got.ID != b.ID {
		t.Fatalf("默认预设应切换到 B: %+v", got)
	}
	list, err := svc.ListPresets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var foundA bool
	for _, p := range list {
		if p.ID == a.ID {
			foundA = true
			if p.IsDefault {
				t.Fatalf("A 不应再是默认: %+v", p)
			}
		}
	}
	if !foundA {
		t.Fatal("列表里找不到预设 A")
	}

	updated, err := svc.UpdatePreset(ctx, b.ID, repo.MonitoringPresetInput{
		Name: nameB, IntervalHours: 48, IsDefault: true,
	}, actor, "127.0.0.1")
	if err != nil || updated.IntervalHours != 48 {
		t.Fatalf("更新预设失败: %+v err=%v", updated, err)
	}
	if _, err := svc.CreatePreset(ctx, repo.MonitoringPresetInput{Name: actor + "-bad", IntervalHours: 0}, actor, "127.0.0.1"); !errors.Is(err, service.ErrMonitoringInput) {
		t.Fatalf("非法间隔应被拒绝，实际 %v", err)
	}

	preview, err := svc.PreviewBulk(ctx, service.PlanBulkRequest{ProjectID: project.ID, Enabled: boolPtr(false)})
	if err != nil || preview.Total != 2 {
		t.Fatalf("批量预览不符: %+v err=%v", preview, err)
	}
	res, err := svc.ApplyBulk(ctx, service.PlanBulkRequest{ProjectID: project.ID, Enabled: boolPtr(false)}, actor, "127.0.0.1")
	if err != nil || res.Updated != 2 {
		t.Fatalf("批量停用失败: %+v err=%v", res, err)
	}
	if p, _ := r.Seeds().GetPlan(ctx, plan1.ID); p.Enabled {
		t.Fatal("plan1 应已停用")
	}
	interval := 6
	res, err = svc.ApplyBulk(ctx, service.PlanBulkRequest{ProjectID: project.ID, IntervalHours: &interval}, actor, "127.0.0.1")
	if err != nil || res.Updated != 2 {
		t.Fatalf("批量改间隔失败: %+v err=%v", res, err)
	}
	if p, _ := r.Seeds().GetPlan(ctx, plan2.ID); p.IntervalHours != 6 {
		t.Fatalf("plan2 间隔应为 6，实际 %d", p.IntervalHours)
	}
	res, err = svc.ApplyBulk(ctx, service.PlanBulkRequest{PlanIDs: []int64{plan1.ID}, Enabled: boolPtr(true)}, actor, "127.0.0.1")
	if err != nil || res.Updated != 1 {
		t.Fatalf("按 ID 批量启用失败: %+v err=%v", res, err)
	}
	if _, err := svc.ApplyBulk(ctx, service.PlanBulkRequest{PlanIDs: []int64{plan1.ID}}, actor, "127.0.0.1"); !errors.Is(err, service.ErrMonitoringInput) {
		t.Fatalf("缺少更新字段应被拒绝，实际 %v", err)
	}

	if err := svc.DeletePreset(ctx, a.ID, actor, "127.0.0.1"); err != nil {
		t.Fatalf("删除预设 A 失败: %v", err)
	}
	if err := svc.DeletePreset(ctx, b.ID, actor, "127.0.0.1"); err != nil {
		t.Fatalf("删除预设 B 失败: %v", err)
	}

	// 富化总览：用 delta 断言，库里已有真实情报
	statsSvc := service.NewEnrichmentStatusService()
	before, err := statsSvc.Status(ctx)
	if err != nil {
		t.Fatalf("富化总览失败: %v", err)
	}
	prefix := actor + "-intel-"
	keys := []string{prefix + "1", prefix + "2"}
	for _, key := range keys {
		if _, err := r.Intels().UpsertIntel(ctx, repo.IntelUpsert{
			UniqueKey: key, Title: "monitor test", Severity: "high", CVE: "CVE-2024-9999",
			SourceName: "monitor-test", Source: "monitor-test",
		}); err != nil {
			t.Fatalf("插入情报失败: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vuln_intel WHERE unique_key = ANY($1)`, keys)
	})
	if err := r.Intels().MarkEnriched(ctx, repo.IntelEnrich{
		UniqueKey: keys[0], GithubPoc: []repo.POCRef{{FullName: "a/b", URL: "https://github.com/a/b", Verdict: "WATCH"}, {FullName: "c/d", Verdict: "ACT"}},
		CVSSScore: 9.8,
	}); err != nil {
		t.Fatalf("标记富化失败: %v", err)
	}
	after, err := statsSvc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Total != before.Total+2 || after.Enriched != before.Enriched+1 ||
		after.WithPOC != before.WithPOC+1 || after.PocTotal != before.PocTotal+2 {
		t.Fatalf("富化 delta 不符: before=%+v after=%+v", before, after)
	}
	var sourceOK bool
	for _, s := range after.BySource {
		if s.Source == "monitor-test" && s.Total == 2 && s.Enriched == 1 && s.PocTotal == 2 {
			sourceOK = true
		}
	}
	if !sourceOK {
		t.Fatalf("按源统计不符: %+v", after.BySource)
	}

	var logs int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM operation_logs WHERE username = $1 AND module = 'monitoring'`, actor).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs < 5 {
		t.Fatalf("监控操作应落审计，实际 %d 条", logs)
	}
}

func boolPtr(v bool) *bool { return &v }
