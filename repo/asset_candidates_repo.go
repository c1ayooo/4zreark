package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// 资产候选：被动发现源（测绘引擎反查 / 证书透明）产出的新资产线索，
// 人工确认后才进资产域。UNIQUE(project_id, kind, value) 天然去重。

type CandidateStatus string

const (
	CandidatePending  CandidateStatus = "pending"
	CandidateAccepted CandidateStatus = "accepted"
	CandidateRejected CandidateStatus = "rejected"
)

type AssetCandidate struct {
	ID         int64      `json:"id"`
	ProjectID  int64      `json:"project_id"`
	Kind       string     `json:"kind"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`
	Confidence int        `json:"confidence"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	DecidedAt  *time.Time `json:"decided_at"`
}

type AssetCandidateRepo interface {
	UpsertCandidates(ctx context.Context, projectID int64, items []AssetCandidate) (int64, error)
	ListCandidates(ctx context.Context, projectID int64, status string, limit int) ([]AssetCandidate, error)
	DecideCandidates(ctx context.Context, projectID int64, ids []int64, accept bool) (int64, error)
	CountPending(ctx context.Context, projectID int64) (int64, error)
}

type assetCandidateRepo struct{ r *Repo }

func (r *Repo) AssetCandidates() AssetCandidateRepo { return &assetCandidateRepo{r: r} }

// UpsertCandidates 批量写入候选（已存在的 pending/decided 同值不覆盖）。
// 返回实际新增条数。
func (c *assetCandidateRepo) UpsertCandidates(ctx context.Context, projectID int64, items []AssetCandidate) (int64, error) {
	if len(items) == 0 {
		return 0, nil
	}
	var inserted int64
	for _, it := range items {
		tag, err := c.r.pool.Exec(ctx, `
insert into asset_candidates (project_id, kind, value, source, confidence)
values ($1, $2, $3, $4, $5)
on conflict (project_id, kind, value) do nothing`,
			projectID, it.Kind, it.Value, it.Source, it.Confidence)
		if err != nil {
			return inserted, err
		}
		inserted += tag.RowsAffected()
	}
	return inserted, nil
}

func (c *assetCandidateRepo) ListCandidates(ctx context.Context, projectID int64, status string, limit int) ([]AssetCandidate, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if status == "" {
		status = string(CandidatePending)
	}
	rows, err := c.r.pool.Query(ctx, `
select id, project_id, kind, value, source, confidence, status, created_at, decided_at
from asset_candidates where project_id = $1 and status = $2
order by created_at desc limit $3`, projectID, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetCandidate{}
	for rows.Next() {
		var c AssetCandidate
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.Kind, &c.Value, &c.Source,
			&c.Confidence, &c.Status, &c.CreatedAt, &c.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (c *assetCandidateRepo) DecideCandidates(ctx context.Context, projectID int64, ids []int64, accept bool) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	status := string(CandidateRejected)
	if accept {
		status = string(CandidateAccepted)
	}
	tag, err := c.r.pool.Exec(ctx, `
update asset_candidates set status = $3, decided_at = now()
where project_id = $1 and id = any($2::bigint[]) and status = 'pending'`,
		projectID, ids, status)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (c *assetCandidateRepo) CountPending(ctx context.Context, projectID int64) (int64, error) {
	var n int64
	err := c.r.pool.QueryRow(ctx,
		`select count(*) from asset_candidates where project_id = $1 and status = 'pending'`,
		projectID).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return n, err
}
