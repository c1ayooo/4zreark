package repo

import (
	"context"
)

// 情报富化总览：给运营页一个「采集了多少、富化了多少、拿到多少 PoC」的口径。
// 只读聚合，不改变任何情报状态。

type EnrichmentSourceStat struct {
	Source   string `json:"source"`
	Total    int64  `json:"total"`
	Enriched int64  `json:"enriched"`
	PocTotal int64  `json:"poc_total"`
}

type EnrichmentStats struct {
	Total    int64                  `json:"total"`
	Enriched int64                  `json:"enriched"`
	WithPOC  int64                  `json:"with_poc"`
	PocTotal int64                  `json:"poc_total"`
	LabOnly  int64                  `json:"lab_only"`
	BySource []EnrichmentSourceStat `json:"by_source"`
}

type IntelOpsRepo struct{ r *Repo }

func (r *Repo) IntelOps() *IntelOpsRepo { return &IntelOpsRepo{r: r} }

func (r *IntelOpsRepo) EnrichmentStats(ctx context.Context) (*EnrichmentStats, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	st := &EnrichmentStats{BySource: []EnrichmentSourceStat{}}
	if err := r.r.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE enriched_at IS NOT NULL),
		       count(*) FILTER (WHERE coalesce(jsonb_array_length(github_poc), 0) > 0),
		       coalesce(sum(coalesce(jsonb_array_length(github_poc), 0)), 0),
		       count(*) FILTER (WHERE lab_only)
		  FROM vuln_intel`).
		Scan(&st.Total, &st.Enriched, &st.WithPOC, &st.PocTotal, &st.LabOnly); err != nil {
		return nil, err
	}

	rows, err := r.r.pool.Query(ctx, `
		SELECT coalesce(nullif(source_name,''), nullif(source,''), 'unknown'),
		       count(*),
		       count(*) FILTER (WHERE enriched_at IS NOT NULL),
		       coalesce(sum(coalesce(jsonb_array_length(github_poc), 0)), 0)
		  FROM vuln_intel
		 GROUP BY 1
		 ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s EnrichmentSourceStat
		if err := rows.Scan(&s.Source, &s.Total, &s.Enriched, &s.PocTotal); err != nil {
			return nil, err
		}
		st.BySource = append(st.BySource, s)
	}
	return st, rows.Err()
}
