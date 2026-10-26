package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 接口视图验收：不依赖 /api 前缀，查询串、路径段、方法和内容类型都能命中；
// 站点视图只返回含接口记录的站点，站点详情分页也支持 interface=1。
func TestInterfaceLens(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("iface%d", time.Now().UnixNano()),
		Name: "interface lens test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	host := "iface.example"
	base := "https://" + host
	assets := repo.NewAssetRepo()
	if _, err := assets.ImportRecords(ctx, project.ID, "scan", []repo.RawRecord{
		{Host: host, Port: 443, Protocol: "https", Value: base + "/about", StatusCode: 200},
		{Host: host, Port: 443, Protocol: "https", Value: base + "/portal/category/allData?type=1", StatusCode: 200},
		{Host: host, Port: 443, Protocol: "https", Value: base + "/gateway/order/list", StatusCode: 200},
		{Host: host, Port: 443, Protocol: "https", Value: base + "/submit",
			StatusCode: 200, Evidence: map[string]any{"method": "POST"}},
	}); err != nil {
		t.Fatalf("导入资产失败: %v", err)
	}

	page, err := assets.ListAssets(ctx, repo.AssetQuery{
		ProjectID: project.ID,
		Kind:      "record",
		View:      "interfaces",
		PageSize:  50,
	})
	if err != nil {
		t.Fatalf("查询接口记录失败: %v", err)
	}
	rows, ok := page.Items.([]*repo.RawRecordRow)
	if !ok {
		t.Fatalf("记录视图返回类型异常: %T", page.Items)
	}
	if len(rows) != 3 {
		t.Fatalf("接口记录 = %d 条，期望 3（about 不算接口）: %+v", len(rows), rows)
	}
	values := map[string]bool{}
	for _, row := range rows {
		values[row.Value] = true
		if !row.IsInterface {
			t.Errorf("接口视图里的记录未标记 is_interface: %s", row.Value)
		}
	}
	if values[base+"/about"] {
		t.Error("普通页面 /about 不应进入接口视图")
	}

	sitePage, err := assets.ListAssets(ctx, repo.AssetQuery{
		ProjectID: project.ID,
		Kind:      "site",
		View:      "interfaces",
		SiteGroup: true,
		PageSize:  50,
	})
	if err != nil {
		t.Fatalf("查询接口站点失败: %v", err)
	}
	if sitePage.Total != 1 {
		t.Fatalf("接口站点 = %d 个，期望 1", sitePage.Total)
	}

	items, _, _, err := assets.ListSiteRecords(ctx, rows[0].SiteID, "", 50, true)
	if err != nil {
		t.Fatalf("站点接口记录分页失败: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("站点接口记录 = %d 条，期望 3", len(items))
	}
	for _, item := range items {
		if !item.IsInterface {
			t.Errorf("站点接口分页返回了非接口记录: %s", item.Value)
		}
	}
}

// 站点列表的 with_recent 只带出最近几条证据，且与站点正确关联。
func TestSiteListWithRecentRecords(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("recent%d", time.Now().UnixNano()),
		Name: "site recent records test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	host := "recent.example"
	base := "https://" + host
	assets := repo.NewAssetRepo()
	records := make([]repo.RawRecord, 0, 8)
	for i, path := range []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"} {
		records = append(records, repo.RawRecord{
			Host: host, Port: 443, Protocol: "https", Value: base + path, StatusCode: 200 + i,
		})
	}
	if _, err := assets.ImportRecords(ctx, project.ID, "scan", records); err != nil {
		t.Fatalf("导入资产失败: %v", err)
	}

	page, err := assets.ListAssets(ctx, repo.AssetQuery{
		ProjectID:          project.ID,
		Kind:               "site",
		SiteGroup:          true,
		PageSize:           20,
		WithRecentRecords:  true,
		RecentRecordsLimit: 3,
	})
	if err != nil {
		t.Fatalf("查询站点失败: %v", err)
	}
	sites, ok := page.Items.([]*repo.Site)
	if !ok || len(sites) != 1 {
		t.Fatalf("站点返回异常: %T %+v", page.Items, page)
	}
	if len(sites[0].RecentRecords) != 3 {
		t.Fatalf("最近记录 = %d 条，期望 3", len(sites[0].RecentRecords))
	}
	// 最新导入的状态码最大，应按时间倒序排在最前。
	if sites[0].RecentRecords[0].StatusCode != 207 {
		t.Fatalf("最近记录顺序不对，首条状态码 = %d", sites[0].RecentRecords[0].StatusCode)
	}
	if sites[0].RecentRecords[0].Value != base+"/h" {
		t.Fatalf("最近记录首条 = %s", sites[0].RecentRecords[0].Value)
	}

	// 不带 with_recent 时完全不做这次查询，字段为空。
	page, err = assets.ListAssets(ctx, repo.AssetQuery{
		ProjectID: project.ID, Kind: "site", SiteGroup: true, PageSize: 20,
	})
	if err != nil {
		t.Fatalf("再次查询站点失败: %v", err)
	}
	sites = page.Items.([]*repo.Site)
	if len(sites[0].RecentRecords) != 0 {
		t.Fatalf("未开启 with_recent 时不应返回最近记录，实际 %d 条", len(sites[0].RecentRecords))
	}
}
