package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// 集成验证（打真实 PG，缺 ZRE_PG_PASSWORD 跳过）：
// httptest 起本地站点 → 建项目/站点/端点 → CheckOne 两级 hash 判定三分支
// → 变更后慢爬任务下发（WatchCrawl）→ 同站 24h 冷却。
func TestSiteWatchCheckOneIntegration(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	// 仓储是包级单例（repo.Default），测试里显式初始化
	cfg := config.LoadConfig("../config/config.yaml")
	if _, err := repo.Open(context.Background(), &cfg.Postgres); err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	var content atomic.Value
	content.Store("<html><body>v1</body></html>")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content.Load().(string)))
	}))
	defer srv.Close()

	assets := repo.NewAssetRepo()
	ctx := context.Background()

	// 一次性项目 + reachable 站点 + HTTP 端点
	code := "sitewatch-" + time.Now().Format("01021504")
	project, err := assets.CreateProject(ctx, repo.ProjectInput{Code: code, Name: "巡检集成测试"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = assets.DeleteProject(ctx, project.ID, code) }()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var portNum int
	fmt.Sscanf(portStr, "%d", &portNum)
	if _, err := assets.ImportRecords(ctx, project.ID, "sitewatch-test", []repo.RawRecord{{
		Host: host, Port: portNum, Protocol: "http", Value: "http://" + host,
	}}); err != nil {
		t.Fatal(err)
	}

	sites, err := repo.Default().Pool().Query(ctx,
		`select id from sites where project_id = $1`, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	var siteID int64
	for sites.Next() {
		if err := sites.Scan(&siteID); err != nil {
			t.Fatal(err)
		}
	}
	sites.Close()
	if siteID == 0 {
		t.Fatal("站点未创建")
	}
	// 置 reachable，让巡检选站逻辑语义一致
	if _, err := repo.Default().Pool().Exec(ctx,
		`update sites set state='reachable' where id=$1`, siteID); err != nil {
		t.Fatal(err)
	}

	svc := &SiteWatchService{notify: notify.GetGlobalManager()}

	// refresh 从库里重读站点快照（真实流程每批 SelectWatchSites 都是新快照，
	// 测试复用同一结构体时必须手动刷新，否则判变基线是陈旧值）
	refresh := func() repo.WatchSite {
		var w repo.WatchSite
		if err := repo.Default().Pool().QueryRow(ctx, `
select id, project_id, host, coalesce(content_hash,''), coalesce(content_text_hash,''),
       content_checked_at, content_changed_at
from sites where id = $1`, siteID).Scan(&w.SiteID, &w.ProjectID, &w.Host,
			&w.ContentHash, &w.TextHash, &w.CheckedAt, &w.ChangedAt); err != nil {
			t.Fatal(err)
		}
		w.Port = portNum
		w.Scheme = "http"
		return w
	}

	watch := refresh()

	// ① 首次见到：记 hash，不算变更
	changed, crawled, err := svc.CheckOne(ctx, watch)
	if err != nil || changed || crawled {
		t.Fatalf("首次应只记 hash: changed=%v crawled=%v err=%v", changed, crawled, err)
	}
	var rawHash, textHash string
	if err := repo.Default().Pool().QueryRow(ctx,
		`select content_hash, content_text_hash from sites where id=$1`, siteID).
		Scan(&rawHash, &textHash); err != nil {
		t.Fatal(err)
	}
	if rawHash == "" || textHash == "" {
		t.Fatal("首次巡检未落 hash")
	}

	// ② raw 变 text 同（加注释）→ 动态噪声
	content.Store("<html><body><!-- noise -->v1</body></html>")
	watch = refresh()
	changed, _, err = svc.CheckOne(ctx, watch)
	if err != nil || changed {
		t.Fatalf("动态噪声不应判变更: changed=%v err=%v", changed, err)
	}

	// ③ text 变 → 真变更 + 慢爬任务（WatchCrawl）
	content.Store("<html><body>v2 完全不同的内容</body></html>")
	watch = refresh()
	changed, crawled, err = svc.CheckOne(ctx, watch)
	if err != nil || !changed {
		t.Fatalf("text 变应判变更: changed=%v err=%v", changed, err)
	}
	if !crawled {
		t.Fatal("变更应下发慢爬任务")
	}
	var watchCrawl bool
	if err := repo.Default().Pool().QueryRow(ctx,
		`select (config->>'watch_crawl')::bool from tasks where project_id=$1 and name like '[站点巡检]%' order by created_at desc limit 1`,
		project.ID).Scan(&watchCrawl); err != nil {
		t.Fatal(err)
	}
	if !watchCrawl {
		t.Fatal("慢爬任务未带 WatchCrawl 标记")
	}

	// ④ 同站冷却：再变更不重复下发
	content.Store("<html><body>v3 又变了</body></html>")
	watch = refresh()
	changed, crawled, err = svc.CheckOne(ctx, watch)
	if err != nil || !changed {
		t.Fatalf("第三次应仍判变更: %v %v", changed, err)
	}
	if crawled {
		t.Fatal("24h 冷却内不应重复下发慢爬")
	}
}

// SelectWatchSites 集成验证（打真实 PG，缺 ZRE_PG_PASSWORD 跳过）。
// P0 回归：lateral 子查询别名循环引用曾让选站 SQL 必然报错，
// 巡检从未跑过而单测全绿——集成测试必须直接覆盖这条 SQL。
// 同时验证：端点同行配对（https 优先）、tcp-only 排除、
// watch_excluded 与项目暂停过滤。
func TestSelectWatchSitesIntegration(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../config/config.yaml")
	if _, err := repo.Open(context.Background(), &cfg.Postgres); err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	assets := repo.NewAssetRepo()
	ctx := context.Background()
	pool := repo.Default().Pool()

	code := "sitewatchsel-" + time.Now().Format("01021504")
	project, err := assets.CreateProject(ctx, repo.ProjectInput{Code: code, Name: "选站集成测试"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = assets.DeleteProject(ctx, project.ID, code) }()

	// 站点 A：http:8080 + https:9443 双端点——必须取同一行的 https/9443，
	// 不能再出现 min(port)/min(scheme) 各自聚合的配对错位
	siteIDByHost := func(host string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx,
			`select id from sites where project_id = $1 and host = $2`, project.ID, host).Scan(&id); err != nil {
			t.Fatalf("站点 %s 未创建: %v", host, err)
		}
		return id
	}

	if _, err := assets.ImportRecords(ctx, project.ID, "sel-test", []repo.RawRecord{{
		Host: "a-sel-test.example.com", Port: 8080, Protocol: "http", Value: "http://a-sel-test.example.com",
	}}); err != nil {
		t.Fatal(err)
	}
	siteAID := siteIDByHost("a-sel-test.example.com")
	if _, err := pool.Exec(ctx,
		`insert into site_endpoints (site_id, scheme, host, port) values ($1, 'https', 'a-sel-test.example.com', 9443)`, siteAID); err != nil {
		t.Fatal(err)
	}

	// 站点 B：tcp-only（把 http 端点换成 tcp）——纯 tcp 站点不应进入巡检
	if _, err := assets.ImportRecords(ctx, project.ID, "sel-test", []repo.RawRecord{{
		Host: "b-sel-test.example.com", Port: 3306, Protocol: "http", Value: "http://b-sel-test.example.com",
	}}); err != nil {
		t.Fatal(err)
	}
	siteBID := siteIDByHost("b-sel-test.example.com")
	if _, err := pool.Exec(ctx, `delete from site_endpoints where site_id = $1`, siteBID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`insert into site_endpoints (site_id, scheme, host, port) values ($1, 'tcp', 'b-sel-test.example.com', 3306)`, siteBID); err != nil {
		t.Fatal(err)
	}

	// 站点状态置 reachable（ImportRecords 初始为 pending）
	if _, err := pool.Exec(ctx,
		`update sites set state='reachable' where id in ($1, $2)`, siteAID, siteBID); err != nil {
		t.Fatal(err)
	}

	// 函数级冒烟：生产入口执行这条 SQL 必须成功——P0 的循环引用别名
	// 在这里会直接报错，这是当初单测拦不住、必须打真库的原因
	if _, err := assets.SelectWatchSites(ctx, 24, 5); err != nil {
		t.Fatalf("SelectWatchSites 执行失败: %v", err)
	}

	// 语义断言：全局队列被存量站点占满时夹具排不进 limit 页（never-checked
	// 的 nulls first + 全库共享一条队列），所以用同一份 SQL 常量按项目过滤。
	// repo 侧改动 SQL 而不改常量时，上面的函数级调用同样会暴露语法/绑定错误。
	selectScoped := func() ([]repo.WatchSite, error) {
		rows, err := pool.Query(ctx, repo.SelectWatchSitesSQL+` and s.project_id = $3
order by s.content_checked_at asc nulls first, s.id limit $2`, 24, 200, project.ID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []repo.WatchSite
		for rows.Next() {
			var w repo.WatchSite
			if err := rows.Scan(&w.SiteID, &w.ProjectID, &w.Host, &w.Port, &w.Scheme,
				&w.Title, &w.ContentHash, &w.TextHash, &w.CheckedAt, &w.ChangedAt); err != nil {
				return nil, err
			}
			out = append(out, w)
		}
		return out, rows.Err()
	}
	findSelected := func(siteID int64) *repo.WatchSite {
		t.Helper()
		sites, err := selectScoped()
		if err != nil {
			t.Fatalf("选站查询报错: %v", err)
		}
		for i := range sites {
			if sites[i].SiteID == siteID {
				return &sites[i]
			}
		}
		return nil
	}

	// ① 站点 A 被选中且端点同行配对（https 优先）
	w := findSelected(siteAID)
	if w == nil {
		t.Fatal("双端点站点应被选中")
	}
	if w.Scheme != "https" || w.Port != 9443 {
		t.Fatalf("端点应同行配对且 https 优先, got %s:%d", w.Scheme, w.Port)
	}

	// ② tcp-only 站点不参与巡检
	if w := findSelected(siteBID); w != nil {
		t.Fatalf("tcp-only 站点不应被选中, got %s:%d", w.Scheme, w.Port)
	}

	// ③ 豁免后不再选中
	if err := assets.SetSiteWatchExcluded(ctx, siteAID, true); err != nil {
		t.Fatal(err)
	}
	if w := findSelected(siteAID); w != nil {
		t.Fatal("watch_excluded 站点不应被选中")
	}
	_ = assets.SetSiteWatchExcluded(ctx, siteAID, false)

	// ④ 项目暂停后整批不选
	if _, err := assets.SetProjectPaused(ctx, project.ID, true, "测试"); err != nil {
		t.Fatal(err)
	}
	if w := findSelected(siteAID); w != nil {
		t.Fatal("项目暂停后不应选中其站点")
	}
	_, _ = assets.SetProjectPaused(ctx, project.ID, false, "")
}
