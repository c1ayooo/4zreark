package test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 路由采集（爬虫 → site_routes）的验收。
//
// 用临时站点 + 真实 PG，不依赖外部爬虫：直接调 SaveCrawledRoutes，
// 断言归属、去重、查询串保留与星图节点。

func TestSaveCrawledRoutes(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	host := "route-test.local"
	key := "route-test-" + time.Now().Format("150405.000000")
	code := fmt.Sprintf("route-test-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	defer func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	}()
	var siteID int64
	err := r.Pool().QueryRow(ctx, `
		INSERT INTO sites (project_id, site_key, host, port, protocol, value, ip, http_status, state, verification_status)
		VALUES ($4, $1, $2, 8080, 'http', $3, '127.0.0.1', 200, 'reachable', 'verified')
		RETURNING id`, key, host, "http://"+host+":8080", projectID).Scan(&siteID)
	if err != nil {
		t.Fatalf("准备临时站点失败: %v", err)
	}
	defer func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM sites WHERE id=$1`, siteID)
	}()

	svc := service.NewAssetService()
	urls := []service.CrawledEndpoint{
		{URL: "http://" + host + ":8080/health", Method: "GET", StatusCode: 200},
		{URL: "http://" + host + ":8080/api/v1/users?id=1", Method: "POST", StatusCode: 201},
		// 同 method+path 重复：只留一条
		{URL: "http://" + host + ":8080/health", Method: "GET", StatusCode: 200},
		// 匹配不到站点：跳过
		{URL: "http://no-such-site.invalid/foo", Method: "GET"},
	}
	sites, saved, err := svc.SaveCrawledRoutes("test", urls)
	if err != nil {
		t.Fatalf("保存路由失败: %v", err)
	}
	if sites != 1 {
		t.Errorf("命中站点数 = %d，期望 1", sites)
	}
	if saved != 2 {
		t.Errorf("写入路由数 = %d，期望 2（重复项去重）", saved)
	}

	routes, err := svc.ListSiteRoutes(siteID, 10)
	if err != nil {
		t.Fatalf("读取路由失败: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("路由条数 = %d，期望 2", len(routes))
	}
	byPath := map[string]*repo.SiteRoute{}
	for _, rt := range routes {
		byPath[rt.Path] = rt
	}
	if _, ok := byPath["/health"]; !ok {
		t.Error("缺少 /health")
	}
	// 查询串要保留，否则 /api?id=1 与 ?id=2 会被合并
	if _, ok := byPath["/api/v1/users?id=1"]; !ok {
		t.Errorf("缺少带查询串的路径，实际: %v", byPath)
	}

	// 星图要能看到 route 节点
	g, err := repo.NewAssetRepo().BuildAssetGraph(ctx, repo.AssetQuery{ProjectID: projectID})
	if err != nil {
		t.Fatalf("建图失败: %v", err)
	}
	found := false
	for _, n := range g.Nodes {
		if n.Kind == "route" && n.SiteID == siteID {
			found = true
			break
		}
	}
	if !found {
		t.Error("资产星图里没有该站点的 route 节点")
	}

	summary := repo.SummarizeAssetGraph(g)
	if summary == nil || !summary.Summary {
		t.Fatal("摘要图未标记 summary")
	}
	if len(summary.Nodes) >= len(g.Nodes) {
		t.Fatalf("摘要节点数 %d 应少于全量 %d", len(summary.Nodes), len(g.Nodes))
	}
	for _, n := range summary.Nodes {
		if n.Kind != "project" && n.Kind != "root_domain" && n.Kind != "ip" {
			t.Fatalf("摘要不应包含 %s 节点", n.Kind)
		}
	}
	if summary.Totals["route"] == 0 {
		t.Error("摘要 totals 缺少 route 计数")
	}
	if summary.Counts["p:"+strconv.FormatInt(projectID, 10)] == nil {
		t.Error("摘要缺少项目层计数")
	}
}
