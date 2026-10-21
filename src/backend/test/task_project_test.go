package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
)

// 任务归属规则：一个任务必须属于一个已存在的项目。
func TestTaskRequiresProject(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := fmt.Sprintf("taskproj-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	})

	svc := service.NewTaskService()
	base := func(pid int64) *models.Task {
		return &models.Task{
			ProjectID:  pid,
			Name:       "task-project-test",
			Type:       models.TaskTypePortScan,
			Targets:    []string{"127.0.0.1"},
			TargetType: "ip",
		}
	}

	if err := svc.CreateTask(base(0)); err == nil || !strings.Contains(err.Error(), "归属项目") {
		t.Fatalf("project_id=0 应被拒绝，实际 err=%v", err)
	}
	if err := svc.CreateTask(base(999999999)); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("不存在的项目应被拒绝，实际 err=%v", err)
	}

	task := base(projectID)
	if err := svc.CreateTask(task); err != nil {
		t.Fatalf("合法项目应创建成功: %v", err)
	}
	t.Cleanup(func() {
		_ = svc.DeleteTask(task.ID.Hex())
	})

	got, err := svc.GetTaskByID(task.ID.Hex())
	if err != nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if got.ProjectID != projectID {
		t.Fatalf("任务 project_id=%d，期望 %d", got.ProjectID, projectID)
	}
}
