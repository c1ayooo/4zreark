package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 巡航触发方式：interval / on_change 的取舍与冷却期。
// 到期计划只看 interval/both，纯 on_change 不会被 DuePlans 捞到；
// 变更计划只认新增/重现/接管三类事件，且必须过了冷却期。
func TestCycleChangeTrigger(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := "cyc-" + time.Now().Format("150405.000000")
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM run_targets WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM runs WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM monitoring_plans WHERE seed_id IN (SELECT id FROM seeds WHERE project_id = $1)`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM seeds WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	var seedID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO seeds (project_id, kind, value, enabled) VALUES ($1,'domain',$2,true) RETURNING id`,
		projectID, code+".test").Scan(&seedID); err != nil {
		t.Fatalf("建种子失败: %v", err)
	}

	// 纯 on_change 计划：不该被 DuePlans 取到。
	var onChangePlan int64
	if err := r.Pool().QueryRow(ctx, `
INSERT INTO monitoring_plans (seed_id, interval_hours, trigger_mode, change_cooldown_minutes, enabled, next_run_at)
VALUES ($1, 24, 'on_change', 10, true, now()) RETURNING id`, seedID).Scan(&onChangePlan); err != nil {
		t.Fatalf("建 on_change 计划失败: %v", err)
	}

	seeds := repo.Default().Seeds()
	due, err := seeds.DuePlans(ctx, 50)
	if err != nil {
		t.Fatalf("查询到期计划失败: %v", err)
	}
	for _, p := range due {
		if p.ID == onChangePlan {
			t.Fatal("on_change 计划不应出现在到期计划里")
		}
	}

	// 没有变更事件时，变更触发集合为空。
	change, err := seeds.ChangeTriggeredPlans(ctx, 50)
	if err != nil {
		t.Fatalf("查询变更触发计划失败: %v", err)
	}
	if len(change) != 0 {
		t.Fatalf("无变更事件时不应触发，实际 %d", len(change))
	}

	// 造一个已过冷却期的变更事件（first_seen），冷却 1 分钟。
	if err := r.Pool().QueryRow(ctx, `
UPDATE monitoring_plans SET change_cooldown_minutes = 1 WHERE id = $1 RETURNING id`, onChangePlan).Scan(new(int64)); err != nil {
		t.Fatalf("调整冷却期失败: %v", err)
	}
	var siteID int64
	if err := r.Pool().QueryRow(ctx, `
INSERT INTO sites (project_id, site_key, host, port, protocol, value, state, discovery_type)
VALUES ($1,$2,$2,443,'https','https://'||$2,'reachable','scan') RETURNING id`,
		projectID, code+".test").Scan(&siteID); err != nil {
		t.Fatalf("建站点失败: %v", err)
	}
	// 事件时间放到 10 分钟前，绕过冷却窗口。
	if _, err := r.Pool().Exec(ctx, `
INSERT INTO asset_events (project_id, site_id, event_type, title, created_at)
VALUES ($1,$2,'first_seen','首次发现', now() - interval '10 minutes')`,
		projectID, siteID); err != nil {
		t.Fatalf("写事件失败: %v", err)
	}

	change, err = seeds.ChangeTriggeredPlans(ctx, 50)
	if err != nil {
		t.Fatalf("二次查询变更触发计划失败: %v", err)
	}
	if len(change) != 1 || change[0].ID != onChangePlan {
		t.Fatalf("有新增事件且过冷却期后应触发一次，实际 %+v", change)
	}

	// 冷却期内的事件不触发：把事件时间改到 10 秒前，冷却 10 分钟。
	if _, err := r.Pool().Exec(ctx, `DELETE FROM asset_events WHERE site_id = $1`, siteID); err != nil {
		t.Fatalf("清理事件失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx, `
UPDATE monitoring_plans SET change_cooldown_minutes = 10 WHERE id = $1`, onChangePlan); err != nil {
		t.Fatalf("调回冷却期失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx, `
INSERT INTO asset_events (project_id, site_id, event_type, title, created_at)
VALUES ($1,$2,'first_seen','刚刚发现', now() - interval '10 seconds')`,
		projectID, siteID); err != nil {
		t.Fatalf("写新事件失败: %v", err)
	}
	change, err = seeds.ChangeTriggeredPlans(ctx, 50)
	if err != nil {
		t.Fatalf("三次查询失败: %v", err)
	}
	if len(change) != 0 {
		t.Fatalf("冷却期内不应触发，实际 %d", len(change))
	}

	// 探测类 attribute_change 不算变更信号。
	if _, err := r.Pool().Exec(ctx, `DELETE FROM asset_events WHERE site_id = $1`, siteID); err != nil {
		t.Fatalf("清理事件失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx, `
INSERT INTO asset_events (project_id, site_id, event_type, title, created_at)
VALUES ($1,$2,'attribute_change','标题变化', now() - interval '10 minutes')`,
		projectID, siteID); err != nil {
		t.Fatalf("写属性事件失败: %v", err)
	}
	change, err = seeds.ChangeTriggeredPlans(ctx, 50)
	if err != nil {
		t.Fatalf("四次查询失败: %v", err)
	}
	if len(change) != 0 {
		t.Fatalf("attribute_change 不应触发，实际 %d", len(change))
	}
}

// 变更触发只推进 last_run_at，不动 next_run_at。
func TestCycleMarkPlanChangeRanKeepsSchedule(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := "cyc2-" + time.Now().Format("150405.000000")
	var projectID, seedID, planID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM monitoring_plans WHERE id = $1`, planID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM seeds WHERE id = $1`, seedID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO seeds (project_id, kind, value, enabled) VALUES ($1,'domain',$2,true) RETURNING id`,
		projectID, code+".test").Scan(&seedID); err != nil {
		t.Fatalf("建种子失败: %v", err)
	}
	next := time.Now().Add(3 * time.Hour)
	if err := r.Pool().QueryRow(ctx, `
INSERT INTO monitoring_plans (seed_id, interval_hours, trigger_mode, change_cooldown_minutes, enabled, next_run_at)
VALUES ($1, 24, 'on_change', 10, true, $2) RETURNING id`, seedID, next.UTC()).Scan(&planID); err != nil {
		t.Fatalf("建计划失败: %v", err)
	}

	if err := repo.Default().Seeds().MarkPlanChangeRan(ctx, planID); err != nil {
		t.Fatalf("MarkPlanChangeRan 失败: %v", err)
	}
	plan, err := repo.Default().Seeds().GetPlan(ctx, planID)
	if err != nil {
		t.Fatalf("读计划失败: %v", err)
	}
	if plan.NextRunAt == nil || !plan.NextRunAt.UTC().Truncate(time.Second).Equal(next.UTC().Truncate(time.Second)) {
		t.Errorf("next_run_at 不应被改动: got=%v want=%v", plan.NextRunAt, next)
	}
	if plan.LastRunAt == nil {
		t.Error("last_run_at 应已更新")
	}
}

// UpdatePlan 的 trigger_mode / cooldown 校验。
func TestCycleUpdatePlanTriggerValidation(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := "cyc3-" + time.Now().Format("150405.000000")
	var projectID, seedID, planID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM monitoring_plans WHERE id = $1`, planID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM seeds WHERE id = $1`, seedID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO seeds (project_id, kind, value, enabled) VALUES ($1,'domain',$2,true) RETURNING id`,
		projectID, code+".test").Scan(&seedID); err != nil {
		t.Fatalf("建种子失败: %v", err)
	}
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO monitoring_plans (seed_id, interval_hours, enabled) VALUES ($1,24,true) RETURNING id`,
		seedID).Scan(&planID); err != nil {
		t.Fatalf("建计划失败: %v", err)
	}

	seeds := repo.Default().Seeds()
	bad := "nope"
	if err := seeds.UpdatePlan(ctx, planID, nil, nil, &bad, nil); err == nil {
		t.Error("非法 trigger_mode 应被拒")
	}
	tooLong := 2000
	if err := seeds.UpdatePlan(ctx, planID, nil, nil, nil, &tooLong); err == nil {
		t.Error("超出范围的冷却期应被拒")
	}
	mode := "both"
	cd := 30
	if err := seeds.UpdatePlan(ctx, planID, nil, nil, &mode, &cd); err != nil {
		t.Fatalf("合法参数应通过: %v", err)
	}
	plan, err := seeds.GetPlan(ctx, planID)
	if err != nil {
		t.Fatalf("读计划失败: %v", err)
	}
	if plan.TriggerMode != "both" || plan.ChangeCooldownMinutes != 30 {
		t.Errorf("更新未生效: mode=%s cooldown=%d", plan.TriggerMode, plan.ChangeCooldownMinutes)
	}
}
