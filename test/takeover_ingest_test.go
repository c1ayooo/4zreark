package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/service/pipeline"
)

// 接管命中要落漏洞（待复核）与资产事件；同一目标重复命中不得产生第二条漏洞。
func TestIngestTakeoverIdempotent(t *testing.T) {
	r := openTestRepo(t)
	ctx := context.Background()

	code := "tko-" + time.Now().Format("150405.000000")
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM asset_events WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM vulnerabilities WHERE name LIKE $1`, "子域名接管：%."+code+".test")
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	var siteID int64
	if err := r.Pool().QueryRow(ctx, `
INSERT INTO sites (project_id, site_key, host, port, protocol, value, state, discovery_type)
VALUES ($1,$2,$2,443,'https','https://'||$2,'pending','scan') RETURNING id`,
		projectID, "vuln."+code+".test").Scan(&siteID); err != nil {
		t.Fatalf("建站点失败: %v", err)
	}

	task := &models.Task{
		ProjectID: projectID, Name: "takeover-test", Type: models.TaskTypeTakeover,
		Targets: []string{code + ".test"}, TargetType: "domain",
	}
	taskSvc := service.NewTaskService()
	if err := taskSvc.CreateTask(task); err != nil {
		t.Fatalf("建任务失败: %v", err)
	}
	t.Cleanup(func() { _ = taskSvc.DeleteTask(task.ID.Hex()) })

	result := pipeline.TakeoverResult{
		Domain: "vuln." + code + ".test", CNAME: "dead.example.net",
		Service: "github-pages", Vulnerable: true,
		Reason: "CNAME 指向未认领的 GitHub Pages",
	}
	service.IngestTakeover(ctx, task, result)
	// 第二次命中：漏洞靠唯一索引去重，事件允许追加（两次是不同的观测）。
	service.IngestTakeover(ctx, task, result)

	vulns, total, err := service.NewVulnService().GetVulnsByTaskID(task.ID.Hex(), 1, 50)
	if err != nil {
		t.Fatalf("查询漏洞失败: %v", err)
	}
	if total != 1 {
		t.Fatalf("接管漏洞应只有 1 条（重复命中去重），实际 %d", total)
	}
	v := vulns[0]
	if v.Severity != models.VulnSeverityHigh {
		t.Errorf("接管漏洞等级应为 high，实际 %s", v.Severity)
	}
	if v.Status != models.VulnStatusNew {
		t.Errorf("接管漏洞应为待复核，实际 %s", v.Status)
	}
	if v.TemplateID != "takeover/github-pages" {
		t.Errorf("模板 ID = %q", v.TemplateID)
	}

	var events int64
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM asset_events WHERE site_id = $1 AND event_type = 'takeover'`, siteID).Scan(&events); err != nil {
		t.Fatalf("查询事件失败: %v", err)
	}
	if events != 2 {
		t.Errorf("两次命中应产生 2 条接管事件，实际 %d", events)
	}
}

// 未判定可接管的命中不落任何东西。
func TestIngestTakeoverSkipsSafeResult(t *testing.T) {
	task := &models.Task{ProjectID: 1, Name: "x", Type: models.TaskTypeTakeover}
	service.IngestTakeover(context.Background(), task, pipeline.TakeoverResult{Domain: "safe.test"})
}
