package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/service"
)

// TestBatchResultWritesInOneTx 验证 worker 回传的多条结果走同一个批量写入口：
// 可去重类型合并，端口等类型保持逐条写入。
func TestBatchResultWritesInOneTx(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskID := oid.NewObjectID()
	cleanup := func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM scan_results WHERE task_id = $1`, taskID.Hex())
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM result_dedup WHERE task_id = $1`, taskID.Hex())
	}
	cleanup()
	t.Cleanup(cleanup)

	results := []*models.ScanResult{
		{
			TaskID: taskID, Type: models.ResultTypeSubdomain,
			Data: map[string]interface{}{"subdomain": "batch.example", "domain": "example"},
		},
		{
			TaskID: taskID, Type: models.ResultTypeSubdomain,
			Data: map[string]interface{}{"subdomain": "batch.example", "domain": "example", "title": "updated"},
		},
		{
			TaskID: taskID, Type: models.ResultTypePort,
			Data: map[string]interface{}{"ip": "192.0.2.10", "port": "443", "service": "https"},
		},
	}

	inserted, updated, err := service.NewResultService().BatchCreateResultPtrsWithDedup(results)
	if err != nil {
		t.Fatalf("批量写入失败: %v", err)
	}
	if inserted != 2 || updated != 1 {
		t.Fatalf("inserted=%d updated=%d，期望 2/1", inserted, updated)
	}

	var rows int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM scan_results WHERE task_id = $1`, taskID.Hex()).Scan(&rows); err != nil {
		t.Fatalf("统计结果失败: %v", err)
	}
	if rows != 2 {
		t.Fatalf("结果行数=%d，期望 2（子域去重后 1 条 + 端口 1 条）", rows)
	}
}
