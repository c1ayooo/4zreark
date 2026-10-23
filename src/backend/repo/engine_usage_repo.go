package repo

import (
	"context"
	"time"
)

// EngineUsageRow 一天的引擎用量。
type EngineUsageRow struct {
	Day     time.Time `json:"day"`
	Engine  string    `json:"engine"`
	Queries int       `json:"queries"`
}

// EngineUsageRepo 引擎查询额度的按天记账。
type EngineUsageRepo interface {
	IncrEngineUsage(ctx context.Context, engine string, n int) error
	GetEngineUsageSince(ctx context.Context, since time.Time) ([]EngineUsageRow, error)
}

type engineUsageRepo struct{ r *Repo }

func (r *Repo) EngineUsage() EngineUsageRepo { return &engineUsageRepo{r: r} }

func (r *engineUsageRepo) IncrEngineUsage(ctx context.Context, engine string, n int) error {
	if n <= 0 {
		return nil
	}
	_, err := r.r.pool.Exec(ctx, `
insert into engine_query_usage (day, engine, queries, updated_at)
values (current_date, $1, $2, now())
on conflict (day, engine) do update set
    queries = engine_query_usage.queries + excluded.queries,
    updated_at = now()`, engine, n)
	return err
}

func (r *engineUsageRepo) GetEngineUsageSince(ctx context.Context, since time.Time) ([]EngineUsageRow, error) {
	rows, err := r.r.pool.Query(ctx, `
select day, engine, queries from engine_query_usage
where day >= $1::date order by day desc, engine`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EngineUsageRow
	for rows.Next() {
		var row EngineUsageRow
		if err := rows.Scan(&row.Day, &row.Engine, &row.Queries); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
