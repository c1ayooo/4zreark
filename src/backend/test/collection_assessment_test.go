package test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// 采集完成综合评估：对真实项目数据聚合资产面与风险面（真 PG）。
func TestCollectionAssessment(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 用麦当劳项目（若被清理则取任意有数字资产的项目）
	var projectID int64
	err := r.Pool().QueryRow(ctx,
		`select id from projects where name = '麦当劳'`).Scan(&projectID)
	if err != nil {
		if err := r.Pool().QueryRow(ctx,
			`select project_id from digital_assets limit 1`).Scan(&projectID); err != nil {
			t.Skip("无可评估项目")
		}
	}

	a, err := service.BuildCollectionAssessment(ctx, projectID, "测试触发")
	if err != nil {
		t.Fatalf("构建评估失败: %v", err)
	}
	if a.ProjectName == "" || a.Trigger != "测试触发" {
		t.Fatalf("基础字段不符: %+v", a)
	}
	if a.Entities < 0 || a.Sites < 0 || a.Seeds < 0 {
		t.Fatalf("计数不应为负: %+v", a)
	}
	if a.DigitalAssets > 0 && len(a.DigitalByKind) == 0 {
		t.Fatalf("有数字资产但无类型分布: %+v", a)
	}
	// 汇总行应包含关键计数
	if !strings.Contains(a.Summary, "主体") || !strings.Contains(a.Summary, "风险") {
		t.Fatalf("汇总文案不符: %q", a.Summary)
	}
	// 风险条目数与 Summary 中的数字一致
	if len(a.Risks) > 0 {
		if !strings.Contains(a.Summary, "风险") {
			t.Fatalf("有风险但汇总未体现")
		}
		for _, rk := range a.Risks {
			if rk == "" {
				t.Fatalf("风险条目为空")
			}
		}
	}
	// 快照应已落表；趋势查询应返回至少一个点（时间升序）
	latest, trend, err := service.ProjectAssessmentTrend(ctx, projectID, 30)
	if err != nil {
		t.Fatalf("趋势查询失败: %v", err)
	}
	if latest == nil || latest.ProjectID != projectID {
		t.Fatalf("最近评估缺失: %+v", latest)
	}
	if len(trend) == 0 || trend[len(trend)-1].TakenAt.Before(trend[0].TakenAt) {
		t.Fatalf("趋势点异常: %d 点", len(trend))
	}

	// 清理注销主体处置：造一条注销实体 + 候选，purge 后应消失
	code := "assess-purge-test"
	var pid int64
	if err := r.Pool().QueryRow(ctx,
		`insert into projects (code, name) values ($1,$2) returning id`, code, code).Scan(&pid); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `delete from digital_candidates where project_id=$1`, pid)
		_, _ = r.Pool().Exec(bg, `delete from enterprise_candidates where project_id=$1`, pid)
		_, _ = r.Pool().Exec(bg, `delete from enterprise_entities where project_id=$1`, pid)
		_, _ = r.Pool().Exec(bg, `delete from projects where id=$1`, pid)
	})
	if _, err := r.Pool().Exec(ctx, `
insert into enterprise_entities (project_id, name, open_status, source)
values ($1,'测试注销公司','注销','test'), ($1,'测试在营公司','在营','test')`, pid); err != nil {
		t.Fatalf("造实体失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx, `
insert into digital_candidates (project_id, kind, name, entity_name)
values ($1,'app','注销公司App','测试注销公司'), ($1,'app','在营公司App','测试在营公司')`, pid); err != nil {
		t.Fatalf("造候选失败: %v", err)
	}
	entities, digitalCand, domainCand, err := service.NewEnterpriseService().PurgeDeadEntities(ctx, pid)
	if err != nil {
		t.Fatalf("purge 失败: %v", err)
	}
	if entities != 1 || digitalCand != 1 {
		t.Fatalf("purge 计数不符: entities=%d digital=%d domain=%d", entities, digitalCand, domainCand)
	}
	var alive int
	if err := r.Pool().QueryRow(ctx,
		`select count(*) from enterprise_entities where project_id=$1 and name='测试在营公司'`, pid).Scan(&alive); err != nil || alive != 1 {
		t.Fatalf("在营主体不应被清理: alive=%d err=%v", alive, err)
	}

	t.Logf("评估: %+v", a)
	t.Logf("Summary: %s", a.Summary)
	t.Logf("Risks: %v", a.Risks)
}
