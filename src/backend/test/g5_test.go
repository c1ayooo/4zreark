package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// G5 验收：事件（first_seen / attribute_change / reappear 的基础写入）
// 与关系图谱（边 + 证据 + 保留策略）打真实 PG，缺密码时跳过。
func TestG5RelationsAndEvents(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := fmt.Sprintf("g5-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1, $2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM relations WHERE project_id = $1`, projectID)
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	assets := repo.NewAssetRepo()
	base := code + ".test"
	records := []repo.RawRecord{
		{Host: "a." + base, Protocol: "https", IP: "10.20.30.40", StatusCode: 200, Title: "A"},
		{Host: "b." + base, Protocol: "https", IP: "10.20.30.40", StatusCode: 200, Title: "B"},
		{Host: base, Protocol: "https", IP: "10.20.30.41", StatusCode: 200, Title: "root"},
		{Host: "www." + base, Protocol: "https", IP: "10.20.30.42", StatusCode: 200, Title: "www"},
	}
	res, err := assets.ImportRecords(ctx, projectID, "g5-test", records)
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if res.NewSites != 4 {
		t.Fatalf("应新建 4 个站点，实际 %d", res.NewSites)
	}

	var firstSeen int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM asset_events WHERE project_id = $1 AND event_type = 'first_seen'`, projectID).
		Scan(&firstSeen); err != nil {
		t.Fatal(err)
	}
	if firstSeen != 4 {
		t.Fatalf("first_seen 事件应为 4，实际 %d", firstSeen)
	}

	// 同一条证据重导但标题变化 -> attribute_change
	if _, err := assets.ImportRecords(ctx, projectID, "g5-test", []repo.RawRecord{
		{Host: "a." + base, Protocol: "https", IP: "10.20.30.40", StatusCode: 200, Title: "A-changed"},
	}); err != nil {
		t.Fatalf("二次导入失败: %v", err)
	}
	var changed int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM asset_events WHERE project_id = $1 AND event_type = 'attribute_change'`, projectID).
		Scan(&changed); err != nil {
		t.Fatal(err)
	}
	if changed < 1 {
		t.Fatal("标题变化应产生 attribute_change 事件")
	}

	relRepo := r.Relations()
	stats, err := relRepo.Rebuild(ctx, projectID)
	if err != nil {
		t.Fatalf("重建关系失败: %v", err)
	}
	if stats["same_ip"] < 1 {
		t.Fatalf("应有 same_ip 关系，实际 %v", stats)
	}
	if stats["domain_parent"] < 2 {
		t.Fatalf("应有 2 条 domain_parent（a/base、www/base），实际 %v", stats)
	}

	graph, err := relRepo.List(ctx, projectID, "", 100)
	if err != nil {
		t.Fatalf("查询图谱失败: %v", err)
	}
	if len(graph.Edges) == 0 || len(graph.Nodes) == 0 {
		t.Fatalf("图谱为空: %+v", graph)
	}
	for _, e := range graph.Edges {
		var n int
		if err := r.Pool().QueryRow(ctx,
			`SELECT count(*) FROM relation_evidence WHERE relation_id = $1`, e.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n < 2 {
			t.Fatalf("关系 %d(%s) 证据不足: %d", e.ID, e.Type, n)
		}
	}

	status, err := relRepo.Status(ctx, projectID)
	if err != nil {
		t.Fatalf("索引状态失败: %v", err)
	}
	if status.Edges != int64(len(graph.Edges)) || status.Evidence < status.Edges*2 {
		t.Fatalf("索引统计不符: %+v", status)
	}

	// 保留策略：造 3 条 10 天前的事件，Prune(keep=10000, days=7) 应删掉。
	for i := 0; i < 3; i++ {
		if _, err := r.Pool().Exec(ctx, `
INSERT INTO asset_events (project_id, site_id, event_type, title, created_at)
SELECT $1, id, 'attribute_change', 'old', now() - interval '10 days'
  FROM sites WHERE project_id = $1 LIMIT 1`, projectID); err != nil {
			t.Fatalf("造旧事件失败: %v", err)
		}
	}
	if _, err := assets.PruneEvents(ctx, 10000, 7); err != nil {
		t.Fatalf("清理事件失败: %v", err)
	}
	var oldLeft int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM asset_events WHERE project_id = $1 AND created_at < now() - interval '7 days'`, projectID).
		Scan(&oldLeft); err != nil {
		t.Fatal(err)
	}
	if oldLeft != 0 {
		t.Fatalf("超过 7 天的事件应被清理，剩余 %d", oldLeft)
	}

	// reappear：把本地站点标成 lost，再真实探测一次 httptest 服务。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>g5</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	if _, err := assets.ImportRecords(ctx, projectID, "g5-probe", []repo.RawRecord{{
		Host: "127.0.0.1", Port: port, Protocol: "http", Value: srv.URL, StatusCode: 200, Title: "probe",
	}}); err != nil {
		t.Fatalf("导入本地探测站点失败: %v", err)
	}
	var probeSiteID int64
	if err := r.Pool().QueryRow(ctx,
		`SELECT id FROM sites WHERE project_id = $1 AND host = '127.0.0.1'`, projectID).Scan(&probeSiteID); err != nil {
		t.Fatalf("查本地站点失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx, `UPDATE sites SET state='lost' WHERE id=$1`, probeSiteID); err != nil {
		t.Fatalf("置 lost 失败: %v", err)
	}
	report, err := service.NewVerifyService().ProbeSite(ctx, probeSiteID)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if report.Verdict != "reachable" {
		t.Fatalf("本地 httptest 服务应可达，实际 %s (%s)", report.Verdict, report.ReasonCode)
	}
	var reappeared int
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM asset_events WHERE project_id = $1 AND site_id = $2 AND event_type = 'reappear'`,
		projectID, probeSiteID).Scan(&reappeared); err != nil {
		t.Fatal(err)
	}
	if reappeared < 1 {
		t.Fatal("lost -> reachable 应写入 reappear 事件")
	}
}
