package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
)

// 默认扫描节点：设置/清除、不可用拒绝、任务创建时落到 task.node_id。
func TestDefaultScanNodeSelection(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc := service.NewNodeSelectionService()
	code := fmt.Sprintf("node-sel-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
		_, _ = svc.SetDefaultNode(context.Background(), "")
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM scanner_nodes WHERE node_id like $1`, "node-sel-%")
	})

	nodeID := "node-sel-" + code
	if _, err := r.Pool().Exec(ctx, `
INSERT INTO scanner_nodes (id, node_id, name, type, status)
VALUES (substr(md5($1),1,24), $1, $1, 'worker', 'online')`, nodeID); err != nil {
		t.Fatalf("建测试节点失败: %v", err)
	}

	// 未设置时为空
	if got := svc.DefaultNodeID(ctx); got != "" {
		t.Fatalf("初始应为空，实际 %q", got)
	}
	// 设置为在线节点
	id, err := svc.SetDefaultNode(ctx, nodeID)
	if err != nil || id != nodeID {
		t.Fatalf("设置默认节点失败: id=%q err=%v", id, err)
	}
	if got := svc.DefaultNodeID(ctx); got != nodeID {
		t.Fatalf("默认节点读取不符: %q", got)
	}
	// 停用的节点不能被设为默认
	if _, err := r.Pool().Exec(ctx,
		`UPDATE scanner_nodes SET status='disabled' WHERE node_id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	// 已保存的默认节点不可用时，解析结果必须为空（任务先入队，等节点恢复）
	if got := svc.ResolveTaskNode(ctx, ""); got != "" {
		t.Fatalf("默认节点不可用时应返回空，实际 %q", got)
	}
	if _, err := svc.SetDefaultNode(ctx, nodeID); err == nil {
		t.Fatal("停用节点不应可设为默认")
	}
	// 清除
	if _, err := svc.SetDefaultNode(ctx, ""); err != nil {
		t.Fatalf("清除默认节点失败: %v", err)
	}
	if got := svc.DefaultNodeID(ctx); got != "" {
		t.Fatalf("清除后应为空，实际 %q", got)
	}
}

// 任务创建：显式 node_id 优先；没带时继承默认节点。
func TestTaskInheritsDefaultNode(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc := service.NewNodeSelectionService()
	code := fmt.Sprintf("task-node-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM scanner_nodes WHERE node_id like $1`, "task-node-%")
		_, _ = svc.SetDefaultNode(context.Background(), "")
	})

	nodeA := "task-node-a-" + code
	nodeB := "task-node-b-" + code
	for _, id := range []string{nodeA, nodeB} {
		if _, err := r.Pool().Exec(ctx, `
INSERT INTO scanner_nodes (id, node_id, name, type, status)
VALUES (substr(md5($1),1,24), $1, $1, 'worker', 'online')`, id); err != nil {
			t.Fatalf("建测试节点失败: %v", err)
		}
	}
	if _, err := svc.SetDefaultNode(ctx, nodeA); err != nil {
		t.Fatalf("设置默认节点失败: %v", err)
	}

	tasks := service.NewTaskService()
	// 1) 不指定节点 → 用默认
	t1 := &models.Task{
		ProjectID: projectID, Name: code + "-inherit", Type: models.TaskTypePortScan,
		Targets: []string{"127.0.0.1"}, TargetType: "ip",
	}
	if err := tasks.CreateTask(t1); err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	if t1.NodeID != nodeA {
		t.Fatalf("应继承默认节点 %s，实际 %s", nodeA, t1.NodeID)
	}
	// 2) 显式指定 → 覆盖默认
	t2 := &models.Task{
		ProjectID: projectID, Name: code + "-explicit", Type: models.TaskTypePortScan,
		Targets: []string{"127.0.0.1"}, TargetType: "ip", NodeID: nodeB,
	}
	if err := tasks.CreateTask(t2); err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	if t2.NodeID != nodeB {
		t.Fatalf("应使用指定节点 %s，实际 %s", nodeB, t2.NodeID)
	}
	// 3) 指定不存在的节点 → 拒绝
	t3 := &models.Task{
		ProjectID: projectID, Name: code + "-missing", Type: models.TaskTypePortScan,
		Targets: []string{"127.0.0.1"}, TargetType: "ip", NodeID: "no-such-node",
	}
	if err := tasks.CreateTask(t3); err == nil {
		t.Fatal("指定不存在的节点应被拒绝")
	}
}
