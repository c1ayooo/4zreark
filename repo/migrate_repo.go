package repo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Mongo → PG 一次性迁移的 SQL 落点（校验/插入/分区）。
// 表名必须来自白名单，绝不接受调用方任意字符串。
var migratableTables = map[string]bool{
	"users": true, "roles": true, "permissions": true, "operation_logs": true, "workspaces": true,
	"tasks": true, "task_templates": true, "task_logs": true, "task_jobs": true,
	"scan_results": true, "result_dedup": true,
	"vulnerabilities": true, "pocs": true, "vuln_reports": true,
	"scanner_nodes": true, "plugins": true, "fingerprint_rules": true, "dictionaries": true,
	"cruise_tasks": true, "cruise_logs": true,
	"vuln_intel": true, "vuln_intel_analysis": true, "vuln_intel_settings": true,
	"token_blacklist": true, "llm_usage": true,
}

type MigrateRepo interface {
	// Columns 返回目标表的列名（按 ordinal_position）。
	Columns(ctx context.Context, table string) ([]string, error)
	// InsertJSONDocs 按给定列清单批量插入：只写文档里实际存在的列，
	// 缺失列交给表默认值；冲突跳过。
	InsertJSONDocs(ctx context.Context, table string, columns []string, docs []string) (int64, error)
	// Count 返回表当前行数（核对用）。
	Count(ctx context.Context, table string) (int64, error)
	// EnsureScanResultPartition 为 scan_results 的某个月建分区（幂等）。
	EnsureScanResultPartition(ctx context.Context, month time.Time) error
}

type migrateRepo struct{ r *Repo }

func (r *Repo) Migrate() MigrateRepo { return &migrateRepo{r: r} }

func (r *migrateRepo) InsertJSONDocs(ctx context.Context, table string, columns []string, docs []string) (int64, error) {
	if !migratableTables[table] {
		return 0, fmt.Errorf("不允许迁移到表 %q", table)
	}
	if len(docs) == 0 || len(columns) == 0 {
		return 0, nil
	}
	quoted := make([]string, len(columns))
	selects := make([]string, len(columns))
	for i, c := range columns {
		quoted[i] = pgx.Identifier{c}.Sanitize()
		selects[i] = fmt.Sprintf("(jsonb_populate_record(null::%s, d::jsonb)).%s", table, quoted[i])
	}
	stmt := fmt.Sprintf(`
insert into %s (%s)
select %s
  from unnest($1::text[]) as d
on conflict do nothing`,
		table, strings.Join(quoted, ", "), strings.Join(selects, ", "))
	tag, err := r.r.pool.Exec(ctx, stmt, docs)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *migrateRepo) Columns(ctx context.Context, table string) ([]string, error) {
	if !migratableTables[table] {
		return nil, fmt.Errorf("不允许读取表 %q 的列", table)
	}
	rows, err := r.r.pool.Query(ctx, `
select column_name
  from information_schema.columns
 where table_schema = current_schema() and table_name = $1
 order by ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *migrateRepo) Count(ctx context.Context, table string) (int64, error) {
	if !migratableTables[table] && table != "scan_results" {
		return 0, fmt.Errorf("不允许统计表 %q", table)
	}
	var n int64
	err := r.r.pool.QueryRow(ctx, fmt.Sprintf(`select count(*) from %s`, table)).Scan(&n)
	return n, err
}

func (r *migrateRepo) EnsureScanResultPartition(ctx context.Context, month time.Time) error {
	// 按 +08:00 切月，与 schema_init.sql 的分区边界一致
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, loc)
	end := start.AddDate(0, 1, 0)
	name := fmt.Sprintf("scan_results_%04d_%02d", start.Year(), int(start.Month()))
	stmt := fmt.Sprintf(`create table if not exists %s partition of scan_results
		for values from ('%s') to ('%s')`,
		pgx.Identifier{name}.Sanitize(),
		start.Format("2006-01-02 15:04:05-07"),
		end.Format("2006-01-02 15:04:05-07"))
	_, err := r.r.pool.Exec(ctx, stmt)
	return err
}
