// Package repo 是数据访问层：唯一允许出现 SQL 字符串、唯一允许 import pgx 的包。
// 上层（service/）只依赖这里的接口，不直接依赖 PostgreSQL 驱动。
package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/config"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 表示记录不存在，service 层据此转成对应的业务错误。
var ErrNotFound = errors.New("record not found")

// ErrDuplicate 表示唯一约束冲突（同一模板+目标的漏洞、同一模板 ID 的 POC 等）。
var ErrDuplicate = errors.New("duplicate record")

// cst 固定用东八区算分区边界：DDL 里的分区是按 +08:00 切的。
var cst = time.FixedZone("CST", 8*3600)

// requiredTables 是启动自检要求必须存在的表。
var requiredTables = []string{
	"users", "tasks", "task_jobs", "scan_results",
	"vulnerabilities", "result_dedup", "token_blacklist", "schema_migrations",
}

var defaultRepo *Repo

// Repo 持有连接池，是所有仓储的入口。
type Repo struct {
	pool   *pgxpool.Pool
	schema string
}

// Open 建立连接池并置为默认仓储。search_path 由 DSN 带入，保证 SQL 里不写 schema 前缀。
func Open(ctx context.Context, cfg *config.PostgresConfig) (*Repo, error) {
	if cfg == nil || cfg.Host == "" {
		return nil, errors.New("postgres 配置缺失（host 为空）")
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("解析 PostgreSQL 连接串失败: %w", err)
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = int32(cfg.MaxConns)
	}
	if cfg.MinConns > 0 {
		poolCfg.MinConns = int32(cfg.MinConns)
	}
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("创建连接池失败: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("连接 PostgreSQL 失败: %w", err)
	}

	r := &Repo{pool: pool, schema: cfg.Schema}
	defaultRepo = r
	return r, nil
}

// Default 返回进程内默认仓储，供未做依赖注入的调用方使用。
func Default() *Repo { return defaultRepo }

// Pool 暴露连接池给同包内的仓储实现使用。
func (r *Repo) Pool() *pgxpool.Pool { return r.pool }

func (r *Repo) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}

func (r *Repo) Ping(ctx context.Context) error { return r.pool.Ping(ctx) }

// SelfCheck 是交接规格 §5 的启动自检，任一项不过就返回错误（调用方以退出码 2 退出）。
func (r *Repo) SelfCheck(ctx context.Context) error {
	var one int
	if err := r.pool.QueryRow(ctx, "select 1").Scan(&one); err != nil {
		return fmt.Errorf("select 1 失败: %w", err)
	}

	var migrated bool
	if err := r.pool.QueryRow(ctx,
		`select exists (select 1 from schema_migrations where name = 'schema_init')`,
	).Scan(&migrated); err != nil {
		return fmt.Errorf("读取迁移账本失败: %w", err)
	}
	if !migrated {
		return errors.New("schema_migrations 缺少 schema_init 记录，请先执行 docs/sql/schema_init.sql")
	}

	rows, err := r.pool.Query(ctx,
		`select table_name from information_schema.tables
		  where table_schema = current_schema() and table_name = any($1::text[])`,
		requiredTables)
	if err != nil {
		return fmt.Errorf("查询表清单失败: %w", err)
	}
	found := make(map[string]bool, len(requiredTables))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("扫描表名失败: %w", err)
		}
		found[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历表清单失败: %w", err)
	}
	for _, t := range requiredTables {
		if !found[t] {
			return fmt.Errorf("缺少必需的表: %s", t)
		}
	}

	now := time.Now()
	for _, t := range []time.Time{now, now.AddDate(0, 1, 0)} {
		if err := r.EnsureMonthPartition(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

// EnsureMonthPartition 保证 t 所在月份的分区存在，不存在则建（对应交接规格 §5 第 4 项）。
func (r *Repo) EnsureMonthPartition(ctx context.Context, t time.Time) error {
	y, m, _ := t.In(cst).Date()
	start := time.Date(y, m, 1, 0, 0, 0, 0, cst)
	end := start.AddDate(0, 1, 0)
	name := fmt.Sprintf("scan_results_%04d_%02d", y, int(m))

	// 表名由上面拼出（纯数字月），仍走 Sanitize 兜一层
	ident := pgx.Identifier{name}.Sanitize()
	stmt := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF scan_results FOR VALUES FROM ('%s') TO ('%s')`,
		ident,
		start.Format("2006-01-02 15:04:05-07:00"),
		end.Format("2006-01-02 15:04:05-07:00"),
	)
	if _, err := r.pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("创建分区 %s 失败: %w", name, err)
	}
	return nil
}

// --- 仓储入口（未实现的返回 nil，逐步补齐） ---

func (r *Repo) Users() UserRepo { return &userRepo{r: r} }

func (r *Repo) Tasks() TaskRepo { return &taskRepo{r: r} }

func (r *Repo) Jobs() JobRepo { return &jobRepo{r: r} }

func (r *Repo) Results() ResultRepo { return &resultRepo{r: r} }

func (r *Repo) Vulns() VulnRepo { return &vulnRepo{r: r} }

func (r *Repo) Pocs() PocRepo { return &pocRepo{r: r} }

func (r *Repo) Plugins() PluginRepo { return &pluginRepo{r: r} }

func (r *Repo) Dictionaries() DictRepo { return &dictRepo{r: r} }

func (r *Repo) Nodes() NodeRepo { return &nodeRepo{r: r} }

func (r *Repo) Cruises() CruiseRepo { return &cruiseRepo{r: r} }

func (r *Repo) Audits() AuditRepo { return &auditRepo{r: r} }

// isUniqueViolation 判断是否唯一约束冲突。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
