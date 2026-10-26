package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// 种子重建计划：预览要能说清「会删掉多少历史」，执行要一次性完成
// 「删旧计划 + 建新计划」。旧计划级联删掉 runs / run_targets。

// SeedOpsRepo 是种子侧生命周期操作的数据入口。
type SeedOpsRepo struct{ r *Repo }

func (r *Repo) SeedOps() *SeedOpsRepo { return &SeedOpsRepo{r: r} }

// SeedPlanSnapshot 是重建前的快照。
type SeedPlanSnapshot struct {
	Seed    *Seed   `json:"seed"`
	Plans   []*Plan `json:"plans"`
	Runs    int64   `json:"runs"`
	Targets int64   `json:"run_targets"`
}

// Snapshot 读取种子的现有计划与将被级联删除的批次数。
func (r *SeedOpsRepo) Snapshot(ctx context.Context, seedID int64) (*SeedPlanSnapshot, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	seed, err := scanSeed(r.r.pool.QueryRow(ctx,
		`SELECT `+seedColumns+` FROM seeds WHERE id = $1`, seedID))
	if errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	rows, err := r.r.pool.Query(ctx,
		`SELECT `+planColumns+planFrom+` WHERE p.seed_id = $1 ORDER BY p.id DESC`, seedID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := []*Plan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	snap := &SeedPlanSnapshot{Seed: seed, Plans: plans}
	if err := r.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM runs r JOIN monitoring_plans p ON p.id = r.plan_id WHERE p.seed_id = $1),
		       (SELECT count(*) FROM run_targets t JOIN runs r ON r.id = t.run_id
		         JOIN monitoring_plans p ON p.id = r.plan_id WHERE p.seed_id = $1)`, seedID).
		Scan(&snap.Runs, &snap.Targets); err != nil {
		return nil, err
	}
	return snap, nil
}

// SeedRestartCounts 是重建时被清理的历史规模。
type SeedRestartCounts struct {
	Plans   int64 `json:"plans"`
	Runs    int64 `json:"runs"`
	Targets int64 `json:"run_targets"`
}

// RestartPlan 删除种子的全部旧计划并新建一个立即到期的计划。
// 新计划的预算缺省为空对象；间隔由调用方校验（1..720）。
func (r *SeedOpsRepo) RestartPlan(ctx context.Context, seedID int64, intervalHours int, budget map[string]any) (*Plan, *SeedRestartCounts, error) {
	if r == nil || r.r == nil {
		return nil, nil, errUninitialized()
	}
	if budget == nil {
		budget = map[string]any{}
	}
	budgetJSON, err := jsonb(budget)
	if err != nil {
		return nil, nil, err
	}

	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)

	var locked int64
	if err := tx.QueryRow(ctx, `SELECT id FROM seeds WHERE id = $1 FOR UPDATE`, seedID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	counts := &SeedRestartCounts{}
	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM monitoring_plans WHERE seed_id = $1),
		       (SELECT count(*) FROM runs r JOIN monitoring_plans p ON p.id = r.plan_id WHERE p.seed_id = $1),
		       (SELECT count(*) FROM run_targets t JOIN runs r ON r.id = t.run_id
		         JOIN monitoring_plans p ON p.id = r.plan_id WHERE p.seed_id = $1)`, seedID).
		Scan(&counts.Plans, &counts.Runs, &counts.Targets); err != nil {
		return nil, nil, err
	}

	if _, err := tx.Exec(ctx, `DELETE FROM monitoring_plans WHERE seed_id = $1`, seedID); err != nil {
		return nil, nil, err
	}

	var planID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO monitoring_plans (seed_id, interval_hours, budget, enabled, next_run_at)
		VALUES ($1, $2, $3, true, now())
		RETURNING id`, seedID, intervalHours, budgetJSON).Scan(&planID); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}

	plan, err := scanPlan(r.r.pool.QueryRow(ctx, `SELECT `+planColumns+planFrom+` WHERE p.id = $1`, planID))
	if err != nil {
		return nil, nil, err
	}
	return plan, counts, nil
}

// SeedDomainCount 是某个 domain 种子在项目内覆盖的站点数。
type SeedDomainCount struct {
	SeedID    int64  `json:"seed_id"`
	Value     string `json:"value"`
	SiteCount int64  `json:"site_count"`
}

// DomainCounts 统计项目下每个 domain 种子的覆盖站点数（含子域）。
// 没有站点的种子返回 0，方便前端区分「未采集」与「采到了但没站点」。
func (r *SeedOpsRepo) DomainCounts(ctx context.Context, projectID int64) ([]*SeedDomainCount, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	if projectID <= 0 {
		return nil, fmt.Errorf("project_id 必填")
	}
	rows, err := r.r.pool.Query(ctx, `
		SELECT se.id, se.value,
		       count(DISTINCT s.id) FILTER (
		           WHERE s.host = se.value OR s.host LIKE '%.' || se.value
		       )
		  FROM seeds se
		  LEFT JOIN sites s ON s.project_id = se.project_id
		 WHERE se.project_id = $1 AND se.kind = 'domain'
		 GROUP BY se.id, se.value
		 ORDER BY se.value`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*SeedDomainCount{}
	for rows.Next() {
		var c SeedDomainCount
		if err := rows.Scan(&c.SeedID, &c.Value, &c.SiteCount); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}
