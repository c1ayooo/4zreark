package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/oid"
)

// 僵尸任务识别：节点离线且任务 5 分钟没更新才回收；节点在线或刚更新的任务不能误杀。
func TestListStaleRunningTasks(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("stale-%d", time.Now().UnixNano())
	offlineNode := suffix + "-offline"
	onlineNode := suffix + "-online"

	_, err := r.Pool().Exec(ctx, `
		INSERT INTO scanner_nodes (id, node_id, name, type, status, last_heartbeat)
		VALUES (substr(md5($1),1,24), $1, $1, 'worker', 'offline', now()-interval '10 minutes'),
		       (substr(md5($2),1,24), $2, $2, 'worker', 'online', now())`,
		offlineNode, onlineNode)
	if err != nil {
		t.Fatalf("建测试节点失败: %v", err)
	}

	type row struct {
		id, node string
	}
	rows := []row{
		{oid.NewObjectID().Hex(), offlineNode},
		{oid.NewObjectID().Hex(), onlineNode},
		{oid.NewObjectID().Hex(), "missing-node"},
	}
	for _, x := range rows {
		if _, err := r.Pool().Exec(ctx, `
			INSERT INTO tasks (id, name, type, status, targets, target_type, node_id, updated_at)
			VALUES ($1, $2, 'custom', 'running', ARRAY['example.com'], 'domain', $3, now()-interval '10 minutes')`,
			x.id, x.id, x.node); err != nil {
			t.Fatalf("建测试任务失败: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, x := range rows {
			_, _ = r.Pool().Exec(context.Background(), `DELETE FROM tasks WHERE id=$1`, x.id)
		}
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM scanner_nodes WHERE node_id IN ($1,$2)`, offlineNode, onlineNode)
	})

	now := time.Now()
	stale, err := r.Tasks().ListStaleRunning(ctx,
		now.Add(-2*time.Minute), now.Add(-5*time.Minute), now.Add(-6*time.Hour))
	if err != nil {
		t.Fatalf("查询僵尸任务失败: %v", err)
	}
	found := map[string]bool{}
	for _, task := range stale {
		found[task.ID.Hex()] = true
	}
	if !found[rows[0].id] {
		t.Error("离线节点上的旧任务应被识别为僵尸")
	}
	if !found[rows[2].id] {
		t.Error("节点不存在且长时间未更新的任务应被识别为僵尸")
	}
	if found[rows[1].id] {
		t.Error("在线节点上的任务不应被误判")
	}
}
