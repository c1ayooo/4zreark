package test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 资产删除链路（DELETE /api/assets/:id + unprotect）打真实 PG：
//  1. 删活跃站点：站点 / 验证流水 / 事件全部消失，raw_records.site_id 置空但证据保留；
//  2. 保护期内删除被拒，报错文案必须带到期时间；
//  3. unprotect 后 protected_until 为 NULL 且可删；
//  4. 列表响应携带 protected_until 字段。
func TestAssetDeleteLifecycle(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("adel%d", time.Now().UnixNano()),
		Name: "asset delete test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	actor := fmt.Sprintf("adel-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM operation_logs WHERE username = $1`, actor)
	})

	assets := repo.NewAssetRepo()
	tag := fmt.Sprintf("adel-%d", time.Now().UnixNano())
	_, err = assets.ImportRecords(ctx, project.ID, "test", []repo.RawRecord{
		{Host: "active-" + tag, Port: 80, Protocol: "http", Value: "http://active-" + tag},
		{Host: "guard-" + tag, Port: 80, Protocol: "http", Value: "http://guard-" + tag},
	})
	if err != nil {
		t.Fatalf("导入测试站点失败: %v", err)
	}
	activeID, err := assets.SiteIDByHost(ctx, project.ID, "active-"+tag)
	if err != nil {
		t.Fatal(err)
	}
	guardID, err := assets.SiteIDByHost(ctx, project.ID, "guard-"+tag)
	if err != nil {
		t.Fatal(err)
	}

	// 活跃站点要带可级联的数据：一条验证流水 + 一条事件；raw_records 由导入产生。
	if err := assets.VerifySite(ctx, activeID, false, 0, "conn_fail"); err != nil {
		t.Fatalf("写入验证流水失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx,
		`INSERT INTO asset_events (project_id, site_id, event_type, title) VALUES ($1,$2,'test','asset-delete 前置事件')`,
		project.ID, activeID); err != nil {
		t.Fatal(err)
	}

	count := func(query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := r.Pool().QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatalf("统计失败 %s: %v", query, err)
		}
		return n
	}
	// siteExists 复用删除前的存在性语义（与 GetSiteForDelete 同一口径）。
	siteExists := func(id int64) bool {
		var id0 int64
		err := r.Pool().QueryRow(ctx, `SELECT id FROM sites WHERE id = $1`, id).Scan(&id0)
		if errors.Is(err, pgx.ErrNoRows) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		return true
	}

	// --- 4. 列表响应携带 protected_until 字段 ---
	listSvc := service.NewAssetService()
	page, err := listSvc.ListAssets(ctx, repo.AssetQuery{ProjectID: project.ID, Kind: "site", SiteGroup: true, Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("列表查询失败: %v", err)
	}
	blob, err := json.Marshal(page.Items)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"protected_until"`) {
		// 未保护时 omitempty 会省略字段，先给 guard 站点设上保护期再验一次。
		if err := service.NewCleanupService().ProtectSite(ctx, guardID, 7); err != nil {
			t.Fatalf("设置保护期失败: %v", err)
		}
		page, err = listSvc.ListAssets(ctx, repo.AssetQuery{ProjectID: project.ID, Kind: "site", SiteGroup: true, Page: 1, PageSize: 10})
		if err != nil {
			t.Fatal(err)
		}
		blob, err = json.Marshal(page.Items)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(blob), `"protected_until"`) {
			t.Fatalf("列表响应缺 protected_until 字段: %s", blob)
		}
	}

	// --- 2. 保护期内删除被拒，文案带到期时间 ---
	svc := service.NewAssetService()
	err = svc.DeleteAsset(ctx, guardID, actor, "127.0.0.1")
	if !errors.Is(err, service.ErrAssetProtected) {
		t.Fatalf("保护期内删除应被拒，实际 err=%v", err)
	}
	var until time.Time
	if err := r.Pool().QueryRow(ctx, `SELECT protected_until FROM sites WHERE id = $1`, guardID).Scan(&until); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(err.Error(), until.Format("2006-01-02")) || !strings.Contains(err.Error(), "请先解除保护") {
		t.Fatalf("报错文案应带到期时间与解除提示，实际 %q", err.Error())
	}

	// --- 3. unprotect 后 protected_until 为 NULL 且可删 ---
	if err := service.NewCleanupService().ClearProtection(ctx, guardID); err != nil {
		t.Fatalf("解除保护失败: %v", err)
	}
	var protectedUntil *time.Time
	if err := r.Pool().QueryRow(ctx, `SELECT protected_until FROM sites WHERE id = $1`, guardID).Scan(&protectedUntil); err != nil {
		t.Fatal(err)
	}
	if protectedUntil != nil {
		t.Fatalf("解除保护后 protected_until 应为 NULL，实际 %v", protectedUntil)
	}
	if err := svc.DeleteAsset(ctx, guardID, actor, "127.0.0.1"); err != nil {
		t.Fatalf("解除保护后删除失败: %v", err)
	}
	if siteExists(guardID) {
		t.Fatal("解除保护后站点应已删除")
	}

	// --- 1. 删活跃站点：级联清验证/事件，raw_records 置空保留 ---
	if got := count(`SELECT count(*) FROM verifications WHERE site_id = $1`, activeID); got == 0 {
		t.Fatal("前置条件失败：删除前应有验证流水")
	}
	if got := count(`SELECT count(*) FROM asset_events WHERE site_id = $1`, activeID); got == 0 {
		t.Fatal("前置条件失败：删除前应有资产事件")
	}
	if got := count(`SELECT count(*) FROM raw_records WHERE site_id = $1`, activeID); got == 0 {
		t.Fatal("前置条件失败：删除前应有原始记录")
	}
	if err := svc.DeleteAsset(ctx, activeID, actor, "127.0.0.1"); err != nil {
		t.Fatalf("删除活跃站点失败: %v", err)
	}
	if siteExists(activeID) {
		t.Fatal("站点应已删除")
	}
	if got := count(`SELECT count(*) FROM verifications WHERE site_id = $1`, activeID); got != 0 {
		t.Fatalf("验证流水应级联清空，剩余 %d", got)
	}
	if got := count(`SELECT count(*) FROM asset_events WHERE site_id = $1`, activeID); got != 0 {
		t.Fatalf("资产事件应级联清空，剩余 %d", got)
	}
	if got := count(`SELECT count(*) FROM raw_records WHERE site_id = $1`, activeID); got != 0 {
		t.Fatalf("raw_records.site_id 应置空，剩余 %d", got)
	}
	// 证据链保留：按导入值找到被置空的 raw_records。
	if got := count(`SELECT count(*) FROM raw_records WHERE site_id IS NULL AND value = $1`, "http://active-"+tag); got == 0 {
		t.Fatal("raw_records 应保留（site_id 置空）")
	}

	// 审计日志落了且失败不回滚由实现保证：这里断言成功路径有日志。
	if got := count(`SELECT count(*) FROM operation_logs WHERE username = $1 AND action = 'asset_delete'`, actor); got == 0 {
		t.Fatal("应写入 asset_delete 审计日志")
	}
}
