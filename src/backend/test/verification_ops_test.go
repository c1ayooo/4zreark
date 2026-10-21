package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 验证域操作面：跨站点历史、批量预览、强制复验、失联删除。
// 全部打真实 PG；删除路径会真实探测，所以可达站点用本地 httptest，
// 失联站点用 127.0.0.2:9（回环内拒绝连接，不依赖外网）。
func TestVerificationOpsLifecycle(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("vops%d", time.Now().UnixNano()),
		Name: "verification ops test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	actor := fmt.Sprintf("vops-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM operation_logs WHERE username = $1`, actor)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><title>alive</title><body>ok</body></html>"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	assets := repo.NewAssetRepo()
	imported, err := assets.ImportRecords(ctx, project.ID, "test", []repo.RawRecord{
		{Host: "127.0.0.1", Port: port, Protocol: "http", Value: fmt.Sprintf("http://127.0.0.1:%d", port)},
		{Host: "127.0.0.2", Port: 9, Protocol: "http", Value: "http://127.0.0.2:9"},
	})
	if err != nil {
		t.Fatalf("导入测试站点失败: %v", err)
	}
	if imported.NewSites != 2 {
		t.Fatalf("应导入 2 个站点，实际 %+v", imported)
	}
	aliveID, err := assets.SiteIDByHost(ctx, project.ID, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	deadID, err := assets.SiteIDByHost(ctx, project.ID, "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}

	// 连续 3 次失败 -> lost
	for i := 0; i < 3; i++ {
		if err := assets.VerifySite(ctx, deadID, false, 0, "conn_fail"); err != nil {
			t.Fatalf("写入失败流水失败: %v", err)
		}
	}

	svc := service.NewVerificationOpsService()

	rows, total, err := svc.List(ctx, repo.VerificationFilter{ProjectID: project.ID})
	if err != nil {
		t.Fatalf("验证历史查询失败: %v", err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("验证历史应有 3 条，实际 total=%d rows=%d", total, len(rows))
	}
	if rows[0].Host != "127.0.0.2" || rows[0].Status != "failed" || rows[0].ReasonCode != "conn_fail" {
		t.Fatalf("验证历史首行不符: %+v", rows[0])
	}
	if _, failed, err := svc.List(ctx, repo.VerificationFilter{ProjectID: project.ID, Status: "failed"}); err != nil || failed != 3 {
		t.Fatalf("按状态过滤失败: total=%d err=%v", failed, err)
	}

	preview, err := svc.PreviewBatch(ctx, repo.AssetQuery{ProjectID: project.ID})
	if err != nil {
		t.Fatalf("批量核验预览失败: %v", err)
	}
	if preview.Total != 2 || len(preview.Sample) != 2 {
		t.Fatalf("预览应覆盖 2 个站点: %+v", preview)
	}
	preview, err = svc.PreviewBatch(ctx, repo.AssetQuery{ProjectID: project.ID, Q: `host="127.0.0.2"`})
	if err != nil || preview.Total != 1 {
		t.Fatalf("DSL 过滤预览不符: %+v err=%v", preview, err)
	}

	// 按筛选条件批量执行：与预览同一口径，实际重置 2 个站点
	batchRes, err := svc.ExecuteBatch(ctx, repo.AssetQuery{ProjectID: project.ID}, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("批量复验失败: %v", err)
	}
	if batchRes.Matched != 2 || batchRes.Requested != 2 || batchRes.Truncated || batchRes.Recheck.Reset != 2 {
		t.Fatalf("批量复验回执不符: %+v", batchRes)
	}

	// 验证统计：失败流水按状态/原因可见
	stats, err := svc.Stats(ctx, project.ID)
	if err != nil {
		t.Fatalf("验证统计失败: %v", err)
	}
	statusCount := map[string]int64{}
	for _, s := range stats.ByStatus {
		statusCount[s.Key] = s.Count
	}
	if statusCount["failed"] < 3 {
		t.Fatalf("失败流水统计不足: %+v", stats.ByStatus)
	}
	var reasonOK bool
	for _, s := range stats.ByReason {
		if s.Key == "conn_fail" && s.Count >= 3 {
			reasonOK = true
		}
	}
	if !reasonOK {
		t.Fatalf("失败原因统计不符: %+v", stats.ByReason)
	}

	// 复验：重置 attempts、state 回到 pending；不存在的 ID 进 skipped
	recheck, err := svc.Recheck(ctx, []int64{deadID, 999999999}, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("强制复验失败: %v", err)
	}
	if recheck.Reset != 1 || recheck.Skipped != 1 || len(recheck.Items) != 1 {
		t.Fatalf("复验回执不符: %+v", recheck)
	}
	var state, vstatus string
	var attempts int
	if err := r.Pool().QueryRow(ctx,
		`SELECT state, verification_status, attempts FROM sites WHERE id = $1`, deadID).
		Scan(&state, &vstatus, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || vstatus != "pending" || attempts != 0 {
		t.Fatalf("复验后站点状态不符: state=%s status=%s attempts=%d", state, vstatus, attempts)
	}

	// 再打回 lost，验证删除前的逐条复核：可达的跳过、不可达的删除
	for i := 0; i < 3; i++ {
		if err := assets.VerifySite(ctx, deadID, false, 0, "conn_fail"); err != nil {
			t.Fatal(err)
		}
	}
	del, err := svc.DeleteLost(ctx, []int64{aliveID, deadID}, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("失联删除失败: %v", err)
	}
	if del.Deleted != 1 || del.Skipped != 1 {
		t.Fatalf("删除回执不符: %+v", del)
	}
	if len(del.DeletedItems) != 1 || del.DeletedItems[0].SiteID != deadID {
		t.Fatalf("应只删除 127.0.0.2: %+v", del.DeletedItems)
	}
	var exists int
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM sites WHERE id = $1`, deadID).Scan(&exists)
	if exists != 0 {
		t.Fatalf("失联站点应已删除，仍存在 %d 行", exists)
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM sites WHERE id = $1`, aliveID).Scan(&exists)
	if exists != 1 {
		t.Fatal("可达站点不应被删除")
	}

	// 审计：复验与删除各至少一条
	var logs int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM operation_logs WHERE username = $1 AND action IN ('verification_recheck','lost_delete')`,
		actor).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs < 2 {
		t.Fatalf("审计日志不足: %d", logs)
	}
}
