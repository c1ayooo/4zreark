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

// 项目生命周期与种子重建计划：采集态口径、confirm_code 保护、
// 预览 token 一次性、重建计划级联清理旧批次。
func TestProjectLifecycleAndSeedRestart(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("pops%d", time.Now().UnixNano()),
		Name: "project ops test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	actor := fmt.Sprintf("pops-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM operation_logs WHERE username = $1`, actor)
	})

	assets := repo.NewAssetRepo()
	if _, err := assets.ImportRecords(ctx, project.ID, "test", []repo.RawRecord{
		{Host: "pops.example", Port: 443, Protocol: "https", Value: "https://pops.example"},
	}); err != nil {
		t.Fatalf("导入站点失败: %v", err)
	}

	projOps := service.NewProjectOpsService()
	state, err := projOps.CollectionState(ctx, project.ID)
	if err != nil {
		t.Fatalf("采集态查询失败: %v", err)
	}
	if state.Sites != 1 || state.Records != 1 || state.Endpoints != 1 {
		t.Fatalf("采集态站点/记录/入口计数不符: %+v", state)
	}
	if state.Seeds != 0 || state.Plans != 0 || state.Runs != 0 {
		t.Fatalf("空项目种子/计划/批次应为 0: %+v", state)
	}

	seeds := r.Seeds()
	seed := &repo.Seed{
		ProjectID:  project.ID,
		Kind:       "domain",
		Value:      "pops.example",
		Capability: map[string]any{"ports": []any{80.0, 443.0}},
		Enabled:    true,
	}
	if err := seeds.CreateSeed(ctx, seed); err != nil {
		t.Fatalf("创建种子失败: %v", err)
	}
	oldPlan := &repo.Plan{
		SeedID:        seed.ID,
		IntervalHours: 12,
		Budget:        map[string]any{"daily_targets": 2},
		Enabled:       true,
	}
	if err := seeds.CreatePlan(ctx, oldPlan); err != nil {
		t.Fatalf("创建计划失败: %v", err)
	}
	state, err = projOps.CollectionState(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Seeds != 1 || state.EnabledSeeds != 1 || state.Plans != 1 || state.EnabledPlans != 1 {
		t.Fatalf("种子/计划计数不符: %+v", state)
	}

	restartSvc := service.NewSeedRestartService()
	preview, err := restartSvc.Preview(ctx, seed.ID, 0, nil)
	if err != nil {
		t.Fatalf("重建预览失败: %v", err)
	}
	if preview.IntervalHours != 12 || len(preview.Plans) != 1 || preview.Plans[0].ID != oldPlan.ID {
		t.Fatalf("预览应继承原计划间隔与计划列表: %+v", preview)
	}
	if preview.Token == "" || time.Until(preview.ExpiresAt) < 14*time.Minute {
		t.Fatalf("预览 token/有效期不符: %+v", preview)
	}

	if _, _, err := restartSvc.Restart(ctx, seed.ID, "not-a-token", actor, "127.0.0.1"); !errors.Is(err, service.ErrSeedRestartInput) {
		t.Fatalf("无效 token 应返回 ErrSeedRestartInput，实际 %v", err)
	}
	newPlan, counts, err := restartSvc.Restart(ctx, seed.ID, preview.Token, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("重建计划失败: %v", err)
	}
	if counts.Plans != 1 || counts.Runs != 0 || counts.Targets != 0 {
		t.Fatalf("重建清理计数不符: %+v", counts)
	}
	if newPlan.ID == oldPlan.ID || newPlan.IntervalHours != 12 || !newPlan.Enabled || newPlan.NextRunAt == nil {
		t.Fatalf("新计划不符: %+v", newPlan)
	}
	if _, _, err := restartSvc.Restart(ctx, seed.ID, preview.Token, actor, "127.0.0.1"); !errors.Is(err, service.ErrSeedRestartInput) {
		t.Fatalf("token 应为一次性，第二次实际 %v", err)
	}

	// confirm_code 不匹配不得删除
	if _, err := projOps.Delete(ctx, project.ID, "wrong-code", actor, "127.0.0.1"); !errors.Is(err, service.ErrProjectInput) {
		t.Fatalf("错误 confirm_code 应被拒绝，实际 %v", err)
	}
	if _, err := projOps.CollectionState(ctx, project.ID); err != nil {
		t.Fatalf("确认码失败后项目不应被删除: %v", err)
	}

	// 导入回执没有外键，删除项目时必须显式清理。
	if _, err := r.Pool().Exec(ctx,
		`INSERT INTO import_batches (project_id, kind, status) VALUES ($1,'digital','committed')`, project.ID); err != nil {
		t.Fatalf("准备导入回执失败: %v", err)
	}
	del, err := projOps.Delete(ctx, project.ID, project.Code, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("永久删除失败: %v", err)
	}
	if del.Sites != 1 || del.Records != 1 || del.Endpoints != 1 || del.Seeds != 1 || del.Plans != 1 {
		t.Fatalf("删除回执计数不符: %+v", del)
	}
	if _, err := projOps.CollectionState(ctx, project.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("删除后项目应不存在，实际 %v", err)
	}
	var batches int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM import_batches WHERE project_id = $1`, project.ID).Scan(&batches); err != nil {
		t.Fatal(err)
	}
	if batches != 0 {
		t.Fatalf("删除项目应清理导入回执，实际剩 %d 条", batches)
	}

	var logs int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM operation_logs WHERE username = $1 AND action IN ('project_delete','seed_restart')`,
		actor).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs < 2 {
		t.Fatalf("项目删除与计划重建都应落审计，实际 %d 条", logs)
	}
}
