// Package testpostgres supplies isolated PostgreSQL databases to integration tests.
// The configured role needs CREATEDB; no objects in the supplied database are changed.
package testpostgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// RequireTestDatabase 拒绝把"测试前清库"打到生产库：TEST_POSTGRES_DSN 指向的
// 库名必须包含 "test"（如 cyberstrike_test / 4zreco_test）。生产库名（如
// cyberstrike）会被直接判定失败。
//
// 背景：多个包的 newTestPGDB 辅助会在每个用例前 TRUNCATE public 全部表。
// 一旦环境变量误指生产库（历史上发生过，30 次清空把用户/会话/资产全删），
// 测试会把线上数据清空。此守卫在任何破坏性语句之前执行。
func RequireTestDatabase(t testing.TB, dsn string) {
	t.Helper()
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil {
		t.Fatalf("TEST_POSTGRES_DSN 不是合法的 postgres URL: %v", err)
	}
	// unix socket DSN（如 postgres://user@/db?host=/var/run/postgresql）的
	// 主机在 query 参数里；TCP DSN 在 u.Host。
	host := u.Host
	if host == "" {
		host = u.Query().Get("host")
	}
	if host == "" {
		t.Fatalf("TEST_POSTGRES_DSN 缺少主机: %s", dsn)
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == "" {
		t.Fatalf("TEST_POSTGRES_DSN 缺少数据库名: %s", dsn)
	}
	if !strings.Contains(strings.ToLower(name), "test") {
		t.Fatalf("拒绝在非测试库上运行会清空数据的测试：库名 %q 不含 \"test\"。"+
			"TEST_POSTGRES_DSN 必须指向专用测试库（如 cyberstrike_test），禁止指向生产库", name)
	}
}

// DSN creates a database per call and drops only that database on test cleanup.
//
// 变量解析见 baseDSNFromEnv：优先 4ZRECO_TEST_POSTGRES_DSN，回退 TEST_POSTGRES_DSN。
// 回退是必需的 —— newTestPGDB（24 个包）读的是 TEST_POSTGRES_DSN，而 CI 只设了那一个；
// 若此处只认专用名，本 helper 的使用方会在 CI 里静默跳过，而覆盖率门禁的
// 「缺 DSN 拒绝假绿」守卫查的是 TEST_POSTGRES_DSN，永远发现不了这个跳过。
// 该 URL 的角色需具备 CREATEDB（每次调用建一个隔离库）。
func DSN(t testing.TB) string {
	t.Helper()
	base := baseDSNFromEnv()
	if base == "" {
		t.Skip("PostgreSQL integration test: set 4ZRECO_TEST_POSTGRES_DSN " +
			"(or TEST_POSTGRES_DSN) to a postgres:// URL; role requires CREATEDB")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		t.Fatal("test DSN (4ZRECO_TEST_POSTGRES_DSN / TEST_POSTGRES_DSN) must be a postgres:// or postgresql:// URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to PostgreSQL test server: %v", err)
	}
	defer admin.Close(context.Background())
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	name := "4zreco_test_" + hex.EncodeToString(random[:])
	identifier := pgx.Identifier{name}.Sanitize()
	// A2 模板克隆（测试提速）：已注册模板迁移器且模板就绪时，隔离库以
	// CREATE DATABASE ... TEMPLATE <tpl> 文件级克隆——省去每测试从零跑全量迁移
	// 与扩展/补表。失败 fail-open 回落 template0 全新路径（行为与改造前一致）。
	if cloneFromTemplate(ctx, t, admin, identifier) {
		registerDropCleanup(t, base, identifier, name)
		return u.String()
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" TEMPLATE template0"); err != nil {
		t.Fatalf("create isolated test database (CREATEDB is required): %v", err)
	}
	// template0 中性化（同上）：回退路径同样强制白板，杜绝脏 template0 传染。
	// 白板连接顺手补 vector 扩展与 enterprise_jobs（原先独立连接且静默 fail-open，
	// 并发连接抖动时跳过 ⇒ 下游 app.New 迁移 v32 假红——2026-10-10 实测）。
	if wConn, wErr := pgx.Connect(ctx, u.String()); wErr == nil {
		if _, dErr := wConn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); dErr != nil {
			t.Logf("isolated schema wipe failed: %v", dErr)
		}
		if _, eErr := wConn.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS vector"); eErr != nil {
			t.Logf("isolated CREATE EXTENSION vector 不可用: %v", eErr)
		}
		if _, jErr := wConn.Exec(ctx, `CREATE TABLE IF NOT EXISTS enterprise_jobs (
			id TEXT PRIMARY KEY, project_id TEXT NOT NULL, owner TEXT NOT NULL,
			provider TEXT NOT NULL, keyword TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running',
			depth INT NOT NULL DEFAULT 1, max_nodes INT NOT NULL DEFAULT 50,
			nodes INT NOT NULL DEFAULT 0, entities INT NOT NULL DEFAULT 0, domains INT NOT NULL DEFAULT 0,
			imported INT NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
			fingerprint_status TEXT NOT NULL DEFAULT 'pending', fingerprint_total INT NOT NULL DEFAULT 0,
			fingerprint_completed INT NOT NULL DEFAULT 0, fingerprint_matched INT NOT NULL DEFAULT 0,
			fingerprint_failed INT NOT NULL DEFAULT 0, fingerprint_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL, finished_at TIMESTAMPTZ)`); jErr != nil {
			t.Logf("isolated enterprise_jobs prep failed: %v", jErr)
		}
		_ = wConn.Close(context.Background())
	}
	u.Path = "/" + name
	u.RawPath = ""
	// 知识库迁移假定 vector 类型存在（embedding vector(1024)）。隔离库从 template0
	// 创建，不继承基础库扩展 —— 在隔离库自身补建（admin 连接还连在基础库上，对它
	// 执行 CREATE EXTENSION 落不到隔离库）。服务器未装 pgvector 包时保持原失败样貌。
	if iso, isoErr := pgx.Connect(ctx, u.String()); isoErr != nil {
		t.Logf("isolated test database: connect for extension setup failed: %v", isoErr)
	} else {
		if _, err := iso.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS vector"); err != nil {
			t.Logf("isolated test database: CREATE EXTENSION vector 不可用（知识库迁移类用例将失败）: %v", err)
		}
		// 迁移 v32 的存量回填语句引用 enterprise_jobs（UPDATE ... FROM enterprise_jobs），
		// 该表在运行期由 enterprise.NewStore 自迁移创建、不在 schema 迁移里——隔离库
		// 须预建空表，否则 NewDB 全量迁移在 v32 硬失败（形状与 internal/database
		// test_helpers 的补建同源）。
		if _, err := iso.Exec(ctx, `CREATE TABLE IF NOT EXISTS enterprise_jobs (
			id TEXT PRIMARY KEY, project_id TEXT NOT NULL, owner TEXT NOT NULL,
			provider TEXT NOT NULL, keyword TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running',
			depth INT NOT NULL DEFAULT 1, max_nodes INT NOT NULL DEFAULT 50,
			nodes INT NOT NULL DEFAULT 0, entities INT NOT NULL DEFAULT 0, domains INT NOT NULL DEFAULT 0,
			imported INT NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
			fingerprint_status TEXT NOT NULL DEFAULT 'pending', fingerprint_total INT NOT NULL DEFAULT 0,
			fingerprint_completed INT NOT NULL DEFAULT 0, fingerprint_matched INT NOT NULL DEFAULT 0,
			fingerprint_failed INT NOT NULL DEFAULT 0, fingerprint_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL, finished_at TIMESTAMPTZ)`); err != nil {
			t.Logf("isolated test database: CREATE TABLE enterprise_jobs 不可用（迁移 v32 类用例将失败）: %v", err)
		}
		_ = iso.Close(context.Background())
	}
	registerDropCleanup(t, base, identifier, name)
	return u.String()
}

// registerDropCleanup 登记隔离库的测试后清理（drop 治理三件套，模板克隆与
// template0 全新路径共用）。超时分段（2026-10-10 实测定案）：安静态 drop 全量
// 迁移库仅 ~0.6s，但共享预算曾把建连排队也算进去——多路并行打满 max_connections
// 时 admin 建连先耗尽预算。拆开：建连 10s / drop 60s；drop 前至多 3 轮
// pg_terminate_backend 清场（把「等持有者自释放 ~28s」变成立即清场）；
// WITH (FORCE) 兜底；>5s 耗时留痕。
func registerDropCleanup(t testing.TB, base, identifier, name string) {
	t.Cleanup(func() {
		connectCtx, connectCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer connectCancel()
		conn, err := pgx.Connect(connectCtx, base)
		if err != nil {
			t.Errorf("connect for test database cleanup: %v", err)
			return
		}
		defer conn.Close(context.Background())
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer dropCancel()
		nameLiteral := "'" + strings.ReplaceAll(name, "'", "''") + "'"
		for round := 0; round < 3; round++ {
			if _, err := conn.Exec(dropCtx,
				"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = "+nameLiteral+
					" AND pid <> pg_backend_pid()"); err != nil {
				break
			}
			var alive int
			if err := conn.QueryRow(dropCtx,
				"SELECT count(*) FROM pg_stat_activity WHERE datname = "+nameLiteral+
					" AND pid <> pg_backend_pid()").Scan(&alive); err != nil || alive == 0 {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		started := time.Now()
		if _, err := conn.Exec(dropCtx, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated test database %s: %v", name, err)
			return
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Logf("drop isolated test database %s took %s (>5s, 基线 ~0.6s——检查连接占用/负载)", name, elapsed)
		}
	})
}

// ── A2 模板克隆（测试提速）──────────────────────────────────────────────
// 进程内首次克隆前构建「已迁移模板库」：template0 全新建库 → vector 扩展 +
// enterprise_jobs 补表 → 调用方注册的迁移器跑全量 schema → 关闭全部连接。
// 此后每个隔离库 CREATE DATABASE ... TEMPLATE <tpl> 文件级克隆（PG 硬限制：
// 模板库必须无活动连接——迁移器返回前必须关净自己的连接）。
// 模板名带版本指纹（SetTemplateMigrator 提供），迁移变更 ⇒ 新名 ⇒ 自动重建，
// 同时清理旧版本模板。任何一步失败 fail-open 回落 template0 全新路径。

var (
	templateMu       sync.Mutex
	templateName     string
	templateVersion  string
	templateReady    bool
	templateMigrator func(ctx context.Context, dsn string) error
)

// SetTemplateMigrator 注册模板库迁移器与版本指纹（须在首个 DSN() 前调用）。
// version 应随 schema 内容变化（本仓以 testdata/migration_freeze.txt 的内容哈希
// 为指纹——冻结守门强制其随任何迁移体变更而更新）。fn 契约：在 dsn 上跑全量
// 迁移，返回前关闭自己建立的全部连接。重复注册同版本幂等；换版本自动失效重建。
func SetTemplateMigrator(version string, fn func(ctx context.Context, dsn string) error) {
	if fn == nil || strings.TrimSpace(version) == "" {
		return
	}
	templateMu.Lock()
	defer templateMu.Unlock()
	if templateReady && templateVersion == version {
		return
	}
	templateVersion = strings.TrimSpace(version)
	templateMigrator = fn
	// 模板名带进程号（2026-10-10 实测：同仓多测试进程并行做模板改造时同名模板
	// 互踩——他方把共享库快照写进同名模板，克隆带脏数据假红）。跨进程零碰撞；
	// 死进程遗留模板由 ensureTemplate 的旧名清扫回收。
	templateName = fmt.Sprintf("4zreco_ttpl_%s_p%d", version, os.Getpid())
	templateReady = false
}

// cloneFromTemplate 尝试从模板克隆隔离库；成功返回 true（调用方跳过扩展/补表——
// 模板已含）。失败记日志返回 false（回落旧路径，不让提速改造弄挂测试）。
func cloneFromTemplate(ctx context.Context, t testing.TB, admin *pgx.Conn, identifier string) bool {
	t.Helper()
	templateMu.Lock()
	migrator, tplName, ready := templateMigrator, templateName, templateReady
	templateMu.Unlock()
	if migrator == nil {
		return false
	}
	if !ready {
		// 全程持锁构建（防并行首建竞争：N 个用例同时首建曾互相踩踏）。
		templateMu.Lock()
		defer templateMu.Unlock()
		if templateReady { // 双检：等待锁期间他人已建好
			// fallthrough 直接克隆
		} else if !ensureTemplate(ctx, t, admin, tplName, migrator) {
			return false
		} else {
			templateReady = true
		}
	}
	tplIdent := pgx.Identifier{tplName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" TEMPLATE "+tplIdent); err != nil {
		t.Logf("template clone failed (falling back to template0): %v", err)
		return false
	}
	return true
}

// ensureTemplate 构建已迁移模板库（幂等：同名已存在直接复用）。返回是否可用。
func ensureTemplate(ctx context.Context, t testing.TB, admin *pgx.Conn, tplName string,
	migrator func(ctx context.Context, dsn string) error) bool {
	t.Helper()
	tplIdent := pgx.Identifier{tplName}.Sanitize()
	tplU, err := url.Parse(baseDSNFromEnv())
	if err != nil {
		t.Logf("parse base DSN for template: %v", err)
		return false
	}
	tplU.Path = "/" + tplName
	tplU.RawPath = ""
	tplDSN := tplU.String()
	var exists bool
	if err := admin.QueryRow(ctx,
		"SELECT count(*)=1 FROM pg_database WHERE datname=$1", tplName).Scan(&exists); err != nil {
		t.Logf("template probe failed: %v", err)
		return false
	}
	if !exists {
		// 清理其它版本的陈旧模板（防越积越多；当前名除外）
		if rows, err := admin.Query(ctx,
			"SELECT datname FROM pg_database WHERE datname LIKE '4zreco\\_tpl\\_%' AND datname <> $1", tplName); err == nil {
			for rows.Next() {
				var old string
				if rows.Scan(&old) == nil {
					_, _ = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{old}.Sanitize()+" WITH (FORCE)")
				}
			}
			rows.Close()
		}
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+tplIdent+" TEMPLATE template0"); err != nil {
			t.Logf("create template database failed: %v", err)
			return false
		}
		// 🔴 template0 中性化（2026-10-10 实测两度被写脏：180 表数据快照/4 表残骸，
		// 来自同机另一测试进程的集群态争抢）：建库后一律清空 public schema 强制白板，
		// 使「无论 template0 处于什么状态」新建库都是纯净空库。
		if wConn, wErr := pgx.Connect(ctx, tplDSN); wErr == nil {
			if _, dErr := wConn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); dErr != nil {
				t.Logf("template schema wipe failed: %v", dErr)
			}
			_ = wConn.Close(context.Background())
		}
		// vector 扩展 + enterprise_jobs 补表（与旧路径同款 SQL，模板内预置；
		// tplDSN 见函数顶——URL 解析改 Path，防双段 path 坏 DSN）。
		prep, err := pgx.Connect(ctx, tplDSN)
		if err != nil {
			t.Logf("connect template for prep failed: %v", err)
			return false
		}
		if _, err := prep.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS vector"); err != nil {
			t.Logf("template CREATE EXTENSION vector 不可用: %v", err)
		}
		if _, err := prep.Exec(ctx, `CREATE TABLE IF NOT EXISTS enterprise_jobs (
			id TEXT PRIMARY KEY, project_id TEXT NOT NULL, owner TEXT NOT NULL,
			provider TEXT NOT NULL, keyword TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running',
			depth INT NOT NULL DEFAULT 1, max_nodes INT NOT NULL DEFAULT 50,
			nodes INT NOT NULL DEFAULT 0, entities INT NOT NULL DEFAULT 0, domains INT NOT NULL DEFAULT 0,
			imported INT NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
			fingerprint_status TEXT NOT NULL DEFAULT 'pending', fingerprint_total INT NOT NULL DEFAULT 0,
			fingerprint_completed INT NOT NULL DEFAULT 0, fingerprint_matched INT NOT NULL DEFAULT 0,
			fingerprint_failed INT NOT NULL DEFAULT 0, fingerprint_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL, finished_at TIMESTAMPTZ)`); err != nil {
			t.Logf("template enterprise_jobs prep failed: %v", err)
		}
		// 🔴 PG 硬限制：TEMPLATE 源库必须无活动连接——迁移前先断开 prep 连接。
		if err := prep.Close(context.Background()); err != nil {
			t.Logf("close template prep connection failed: %v", err)
			return false
		}
		migCtx, migCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer migCancel()
		if err := migrator(migCtx, tplDSN); err != nil {
			// 迁移失败模板作废：drop 防半成品同名占位
			_, _ = admin.Exec(ctx, "DROP DATABASE "+tplIdent+" WITH (FORCE)")
			t.Logf("template migrator failed (falling back): %v", err)
			return false
		}
		// 种子数据清空（与旧共享库路径的「TRUNCATE 后空库假设」等价）：NewDB 自举
		// 会建 admin 等种子行（实测 rbac_users=admin 曾致克隆库固定唯一键假红），
		// 模板必须是「全 schema + 零业务数据」——迁移后清空全部业务表，schema 不动。
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanCancel()
		if clean, cerr := pgx.Connect(cleanCtx, tplDSN); cerr == nil {
			if _, terr := clean.Exec(cleanCtx, `
				DO $$ DECLARE r record; BEGIN
					FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname='public') LOOP
						EXECUTE 'TRUNCATE TABLE public.' || quote_ident(r.tablename) || ' CASCADE';
					END LOOP;
				END $$`); terr != nil {
				t.Logf("template seed truncate failed: %v", terr)
			}
			_ = clean.Close(context.Background())
		}
	}
	// 模板就绪校验一：必须零活动连接才能作 TEMPLATE。
	var active int
	if err := admin.QueryRow(ctx,
		"SELECT count(*) FROM pg_stat_activity WHERE datname=$1 AND pid <> pg_backend_pid()", tplName).Scan(&active); err != nil || active > 0 {
		t.Logf("template has %d active connections (migrator must close all): %v", active, err)
		return false
	}
	// 模板就绪校验零（半建壳守门）：历史上 prep/migrator 失败会留下同名空壳库，
	// exists 探测命中后被永远复用（克隆缺表 → 每测试全量迁移、且部分用例拿到
	// 非预期 schema）。schema 骨架三表缺失 ⇒ 作废重建。
	if vConn, vErr := pgx.Connect(ctx, tplDSN); vErr == nil {
		var hasSchema int
		if err := vConn.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&hasSchema); err == nil && hasSchema < 150 {
			_ = vConn.Close(context.Background())
			t.Logf("template is a bare shell (%d tables, want ≥150) — rebuilding", hasSchema)
			if _, err := admin.Exec(ctx, "DROP DATABASE "+tplIdent+" WITH (FORCE)"); err != nil {
				t.Logf("drop shell template failed: %v", err)
				return false
			}
			return ensureTemplate(ctx, t, admin, tplName, migrator)
		}
		_ = vConn.Close(context.Background())
	}
	// 模板就绪校验二（污染守门）：模板必须是零业务数据的干净 schema——曾实测模板
	// 被共享库快照污染（15 项目/196 会话），克隆把脏数据带进每个测试（projects
	// 主键冲突假红）。任何业务表有行 ⇒ 模板作废重建，重建仍脏则弃用模板回落旧路径。
	verCtx, verCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer verCancel()
	verConn, verErr := pgx.Connect(verCtx, tplDSN)
	if verErr != nil {
		t.Logf("template cleanliness check connect failed: %v", verErr)
		return false
	}
	var dirty int
	if err := verConn.QueryRow(verCtx,
		`SELECT (SELECT count(*) FROM projects)+(SELECT count(*) FROM conversations)+(SELECT count(*) FROM vulnerabilities)`).Scan(&dirty); err == nil && dirty > 0 {
		_ = verConn.Close(context.Background())
		t.Logf("template polluted (%d business rows) — dropping and rebuilding", dirty)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+tplIdent+" WITH (FORCE)"); err != nil {
			t.Logf("drop polluted template failed: %v", err)
			return false
		}
		if !ensureTemplate(ctx, t, admin, tplName, migrator) { // 重建一次（递归一层）
			return false
		}
		return true
	}
	if err := verConn.Close(context.Background()); err != nil {
		t.Logf("close template verify connection failed: %v", err)
		return false
	}
	return true
}

// baseDSNFromEnv 解析测试库基础 DSN：优先专用变量 4ZRECO_TEST_POSTGRES_DSN，
// 回退到全仓通用的 TEST_POSTGRES_DSN（newTestPGDB 与 CI 用的是后者）。
// 两个变量名并存是历史遗留；这里做兼容回退，避免 CI 里本 helper 的使用方静默跳过。
func baseDSNFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("4ZRECO_TEST_POSTGRES_DSN")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("TEST_POSTGRES_DSN"))
}
