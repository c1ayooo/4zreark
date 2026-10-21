package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/oid"
)

// FpSyncRule 一条待导入的表达式规则。
type FpSyncRule struct {
	Name       string
	Category   string
	Expression string
	RuleHash   string
}

// FpSourceMeta 上游同步元数据。
type FpSourceMeta struct {
	Name        string    `json:"name"`
	UpstreamURL string    `json:"upstream_url"`
	ContentHash string    `json:"content_hash"`
	RuleCount   int       `json:"rule_count"`
	Skipped     int       `json:"skipped_count"`
	FetchedAt   time.Time `json:"fetched_at"`
}

// FingerprintSyncRepo 指纹规则同步仓储（T10）。
type FingerprintSyncRepo interface {
	// ImportUpstream 按 name 幂等 upsert、按 source 清理失效规则。
	// 只更新同 source 的行：custom / legacy / 手工导入的规则不会被覆盖。
	ImportUpstream(ctx context.Context, source, upstreamURL, contentHash string, rules []FpSyncRule, skipped int) (int, error)
	// CountBySource 按来源统计条数（验收用）。
	CountBySource(ctx context.Context) (map[string]int, error)
	// ListSources 返回各源最近一次同步元数据。
	ListSources(ctx context.Context) ([]FpSourceMeta, error)
}

type fingerprintSyncRepo struct{ r *Repo }

// FingerprintSync 返回指纹同步仓储。
func (r *Repo) FingerprintSync() FingerprintSyncRepo { return &fingerprintSyncRepo{r: r} }

func (r *fingerprintSyncRepo) ImportUpstream(ctx context.Context, source, upstreamURL, contentHash string, rules []FpSyncRule, skipped int) (int, error) {
	if len(rules) == 0 {
		return 0, fmt.Errorf("导入集合为空，拒绝导入")
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	names := make([]string, 0, len(rules))
	imported := 0
	for _, rule := range rules {
		names = append(names, rule.Name)
		tag, err := tx.Exec(ctx, `
INSERT INTO fingerprint_rules (id, name, category, expression, rule_hash, enabled, source, updated_at)
VALUES ($1, $2, $3, $4, $5, true, $6, now())
ON CONFLICT (name) DO UPDATE
   SET category   = EXCLUDED.category,
       expression = EXCLUDED.expression,
       rule_hash  = EXCLUDED.rule_hash,
       enabled    = true,
       updated_at = now()
 WHERE fingerprint_rules.source = EXCLUDED.source`,
			oid.NewObjectID().Hex(), rule.Name, rule.Category, rule.Expression, rule.RuleHash, source)
		if err != nil {
			return 0, fmt.Errorf("upsert 规则 %s: %w", rule.Name, err)
		}
		if tag.RowsAffected() > 0 {
			imported++
		}
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM fingerprint_rules WHERE source = $1 AND name <> ALL($2::text[])`,
		source, names); err != nil {
		return 0, fmt.Errorf("清理失效规则: %w", err)
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO fingerprint_sources (name, upstream_url, content_hash, rule_count, skipped_count, fetched_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (name) DO UPDATE
   SET upstream_url = EXCLUDED.upstream_url,
       content_hash = EXCLUDED.content_hash,
       rule_count   = EXCLUDED.rule_count,
       skipped_count = EXCLUDED.skipped_count,
       fetched_at   = now()`,
		source, upstreamURL, contentHash, len(rules), skipped); err != nil {
		return 0, fmt.Errorf("更新来源元数据: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return imported, nil
}

func (r *fingerprintSyncRepo) CountBySource(ctx context.Context) (map[string]int, error) {
	rows, err := r.r.pool.Query(ctx,
		`SELECT coalesce(source, ''), count(*) FROM fingerprint_rules GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var source string
		var n int
		if err := rows.Scan(&source, &n); err != nil {
			return nil, err
		}
		out[source] = n
	}
	return out, rows.Err()
}

func (r *fingerprintSyncRepo) ListSources(ctx context.Context) ([]FpSourceMeta, error) {
	rows, err := r.r.pool.Query(ctx, `
SELECT name, upstream_url, content_hash, rule_count, skipped_count, fetched_at
  FROM fingerprint_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]FpSourceMeta, 0, 4)
	for rows.Next() {
		var m FpSourceMeta
		if err := rows.Scan(&m.Name, &m.UpstreamURL, &m.ContentHash, &m.RuleCount, &m.Skipped, &m.FetchedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
