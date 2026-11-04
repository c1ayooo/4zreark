package repo

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
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

	if _, err := r.pruneStaleRules(ctx, tx, source, names); err != nil {
		return 0, err
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

// pruneStaleRules 清理本轮已不在上游集合内的同源规则。
//
// 两件事必须在这里做，否则「命中表莫名其妙变少」会再次成为无据可查的悬案：
//  1. 删除规则会通过 fingerprint_hits.rule_id 的外键 ON DELETE CASCADE 连带
//     删掉这些规则的历史命中行——这是静默的，任何日志里都不会出现；
//  2. 上游拉取被截断（代理超时、CDN 返回半截 JSON）时，规则集合会「合法地」
//     少掉一大片，按差集删下去等于把规则库和命中历史一起推平。所以集合大幅
//     收缩时只告警不删除，宁可留几条过时规则，也不要丢掉已经验证过的历史。
func (r *fingerprintSyncRepo) pruneStaleRules(ctx context.Context, tx pgx.Tx, source string, names []string) (int64, error) {
	var existing int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM fingerprint_rules WHERE source = $1`, source).Scan(&existing); err != nil {
		return 0, fmt.Errorf("统计同源规则: %w", err)
	}
	if existing == 0 {
		return 0, nil
	}
	// 20% 收缩阈值：正常的上游迭代是几十条级的增删，成片消失多半是抓取不完整。
	if shouldSkipPrune(existing, len(names)) {
		log.Printf("[FpSync] 规则集合异常收缩，跳过失效清理: source=%s 库内 %d 条，本轮 %d 条（可能上游抓取不完整；如需强制清理请先核对来源）",
			source, existing, len(names))
		return 0, nil
	}

	// 先数出将被级联删除的命中行，让「删规则」这件事的副作用可审计。
	var cascaded int64
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM fingerprint_hits fh
		  JOIN fingerprint_rules fr ON fr.id = fh.rule_id
		 WHERE fr.source = $1 AND fr.name <> ALL($2::text[])`,
		source, names).Scan(&cascaded); err != nil {
		return 0, fmt.Errorf("统计失效规则命中: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM fingerprint_rules WHERE source = $1 AND name <> ALL($2::text[])`,
		source, names)
	if err != nil {
		return 0, fmt.Errorf("清理失效规则: %w", err)
	}
	if n := tag.RowsAffected(); n > 0 || cascaded > 0 {
		log.Printf("[FpSync] 清理失效规则: source=%s 删除规则 %d 条，连带删除历史命中 %d 行", source, n, cascaded)
	}
	return tag.RowsAffected(), nil
}

// shouldSkipPrune 判断本轮规则集合是否「收缩得不正常」，不该按差集删除。
// 抽成纯函数是为了能单测：这个阈值的判断错了会静默毁掉规则库和命中历史。
func shouldSkipPrune(existing, incoming int) bool {
	if existing < 50 {
		return false // 小集合（自定义规则）波动正常，按差集清理即可
	}
	return incoming*5 < existing*4
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
