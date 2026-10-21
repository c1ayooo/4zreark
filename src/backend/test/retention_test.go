package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 保留策略：dry-run 只统计；真实清理删旧留新；原始记录的引用被摘掉，
// 失证据的关系边一并清理。
func TestRetentionPolicy(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("ret%d", time.Now().UnixNano()),
		Name: "retention test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	actor := fmt.Sprintf("ret-%d", time.Now().UnixNano())
	scanIDs := []string{oid.NewObjectID().Hex(), oid.NewObjectID().Hex()}
	t.Cleanup(func() {
		for _, id := range scanIDs {
			_, _ = r.Pool().Exec(context.Background(), `DELETE FROM scan_results WHERE id = $1`, id)
		}
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM relations WHERE project_id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM operation_logs WHERE username = $1`, actor)
	})

	assets := repo.NewAssetRepo()
	if _, err := assets.ImportRecords(ctx, project.ID, "test", []repo.RawRecord{
		{Host: "127.0.0.1", Port: 443, Protocol: "https", Value: "https://127.0.0.1"},
		{Host: "127.0.0.2", Port: 443, Protocol: "https", Value: "https://127.0.0.2"},
	}); err != nil {
		t.Fatalf("导入测试站点失败: %v", err)
	}
	siteA, err := assets.SiteIDByHost(ctx, project.ID, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	siteB, err := assets.SiteIDByHost(ctx, project.ID, "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	left, right := siteA, siteB
	if left > right {
		left, right = right, left
	}

	var oldRaw, freshRaw int64
	if err := r.Pool().QueryRow(ctx, `
		INSERT INTO raw_records (project_id, site_id, source, host, port, protocol, value, dedup_key, observed_at)
		VALUES ($1,$2,'test','old.example',443,'https','https://old.example',$3, now() - interval '2 days')
		RETURNING id`, project.ID, siteA, actor+"-old").Scan(&oldRaw); err != nil {
		t.Fatalf("插入旧原始记录失败: %v", err)
	}
	if err := r.Pool().QueryRow(ctx, `
		INSERT INTO raw_records (project_id, site_id, source, host, port, protocol, value, dedup_key, observed_at)
		VALUES ($1,$2,'test','new.example',443,'https','https://new.example',$3, now())
		RETURNING id`, project.ID, siteA, actor+"-new").Scan(&freshRaw); err != nil {
		t.Fatalf("插入新原始记录失败: %v", err)
	}

	if _, err := r.Pool().Exec(ctx, `
		INSERT INTO verifications (site_id, status, reason_code, observed_at)
		VALUES ($1,'failed','conn_fail', now() - interval '2 days'),
		       ($1,'verified','http_ok', now())`, siteA); err != nil {
		t.Fatalf("插入验证流水失败: %v", err)
	}
	for i, id := range scanIDs {
		at := "now()"
		if i == 0 {
			at = "now() - interval '2 days'"
		}
		if _, err := r.Pool().Exec(ctx, fmt.Sprintf(`
			INSERT INTO scan_results (id, task_id, type, created_at)
			VALUES ($1, $2, 'url', %s)`, at), id, oid.NewObjectID().Hex()); err != nil {
			t.Fatalf("插入扫描结果失败: %v", err)
		}
	}
	if _, err := r.Pool().Exec(ctx, `
		INSERT INTO asset_events (project_id, site_id, event_type, title, created_at)
		VALUES ($1,$2,'attribute_change','old event', now() - interval '2 days'),
		       ($1,$2,'attribute_change','new event', now())`, project.ID, siteA); err != nil {
		t.Fatalf("插入事件失败: %v", err)
	}

	var relID int64
	if err := r.Pool().QueryRow(ctx, `
		INSERT INTO relations (project_id, type, key, left_site_id, right_site_id)
		VALUES ($1,'same_ip','127.0.0.1',$2,$3) RETURNING id`, project.ID, left, right).Scan(&relID); err != nil {
		t.Fatalf("插入关系失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx,
		`INSERT INTO relation_evidence (relation_id, record_id) VALUES ($1,$2)`, relID, oldRaw); err != nil {
		t.Fatalf("插入关系证据失败: %v", err)
	}

	svc := service.NewRetentionServiceWithPolicy(service.RetentionPolicy{
		ScanResultsDays: 1, RawRecordsDays: 1, VerificationsDays: 1,
		EventsKeep: 10000, EventsDays: 1, BatchLimit: 100,
	})

	dry, err := svc.RunOnce(ctx, true, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("dry-run 失败: %v", err)
	}
	if dry.ScanResults < 1 || dry.RawRecords < 1 || dry.Verifications < 1 || dry.Events < 1 {
		t.Fatalf("dry-run 计数不符: %+v", dry)
	}
	var n int
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM raw_records WHERE id = $1`, oldRaw).Scan(&n)
	if n != 1 {
		t.Fatal("dry-run 不应删除数据")
	}

	rep, err := svc.RunOnce(ctx, false, actor, "127.0.0.1")
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if rep.ScanResults < 1 || rep.RawRecords < 1 || rep.Verifications < 1 || rep.Events < 1 {
		t.Fatalf("清理计数不符: %+v", rep)
	}

	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM raw_records WHERE id = $1`, oldRaw).Scan(&n)
	if n != 0 {
		t.Fatal("旧原始记录应被清理")
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM raw_records WHERE id = $1`, freshRaw).Scan(&n)
	if n != 1 {
		t.Fatal("新原始记录不应被清理")
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM verifications WHERE site_id = $1 AND status = 'failed'`, siteA).Scan(&n)
	if n != 0 {
		t.Fatal("旧验证流水应被清理")
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM verifications WHERE site_id = $1 AND status = 'verified'`, siteA).Scan(&n)
	if n != 1 {
		t.Fatal("新验证流水不应被清理")
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM scan_results WHERE id = $1`, scanIDs[0]).Scan(&n)
	if n != 0 {
		t.Fatal("旧扫描结果应被清理")
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM scan_results WHERE id = $1`, scanIDs[1]).Scan(&n)
	if n != 1 {
		t.Fatal("新扫描结果不应被清理")
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM relations WHERE id = $1`, relID).Scan(&n)
	if n != 0 {
		t.Fatal("失去全部证据的关系边应被清理")
	}
	_ = r.Pool().QueryRow(ctx, `SELECT count(*) FROM asset_events WHERE project_id = $1 AND title = 'old event'`, project.ID).Scan(&n)
	if n != 0 {
		t.Fatal("旧事件应被清理")
	}

	var logs int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM operation_logs WHERE username = $1 AND action = 'retention_run'`, actor).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs != 1 {
		t.Fatalf("真实清理应落一条审计，实际 %d", logs)
	}
}
