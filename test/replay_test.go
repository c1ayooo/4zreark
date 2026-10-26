package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
)

// 历史 scan_results 回放：按任务归属项目生成 raw_records/sites，重复回放幂等。
func TestReplayScanResults(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := fmt.Sprintf("replay-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}

	taskSvc := service.NewTaskService()
	task := &models.Task{
		ProjectID: projectID, Name: "replay-task", Type: models.TaskTypeFull,
		Targets: []string{code + ".test"}, TargetType: "domain",
	}
	if err := taskSvc.CreateTask(task); err != nil {
		t.Fatalf("建任务失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM scan_results WHERE task_id=$1`, task.ID.Hex())
		_ = taskSvc.DeleteTask(task.ID.Hex())
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id=$1`, projectID)
	})

	resSvc := service.NewResultService()
	results := []models.ScanResult{
		{TaskID: task.ID, WorkspaceID: task.WorkspaceID, Type: models.ResultTypeSubdomain,
			Data: map[string]any{"url": "https://a." + code + ".test", "full_domain": "a." + code + ".test",
				"status_code": 200, "title": "A", "ips": []string{"10.0.0.5"}, "technologies": []string{"nginx"}}},
		{TaskID: task.ID, WorkspaceID: task.WorkspaceID, Type: models.ResultTypeService,
			Data: map[string]any{"host": "b." + code + ".test", "port": 8080, "status_code": 403, "title": "B"}},
		{TaskID: task.ID, WorkspaceID: task.WorkspaceID, Type: models.ResultTypePort,
			Data: map[string]any{"host": "c." + code + ".test", "port": 22, "service": "ssh"}},
	}
	for i := range results {
		if err := resSvc.CreateResult(&results[i]); err != nil {
			t.Fatalf("写扫描结果失败: %v", err)
		}
	}

	replay := service.NewReplayService()
	stats, err := replay.Replay(ctx, projectID, 1000)
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}
	if stats.Results != 3 || stats.Skipped != 0 || stats.Records < 3 || stats.NewSites < 3 {
		t.Fatalf("回放统计不符: %+v", stats)
	}

	var rawCount, siteCount int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM raw_records WHERE project_id=$1`, projectID).Scan(&rawCount); err != nil {
		t.Fatal(err)
	}
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM sites WHERE project_id=$1`, projectID).Scan(&siteCount); err != nil {
		t.Fatal(err)
	}
	if rawCount != 3 || siteCount != 3 {
		t.Fatalf("回放结果不符: raw=%d sites=%d", rawCount, siteCount)
	}

	// 重复回放：命中同一 dedup_key，不新增站点
	again, err := replay.Replay(ctx, projectID, 1000)
	if err != nil {
		t.Fatalf("二次回放失败: %v", err)
	}
	if again.NewSites != 0 || again.Duplicates < 2 {
		t.Fatalf("二次回放应幂等: %+v", again)
	}
}
