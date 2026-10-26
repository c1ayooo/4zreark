package repo

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// 数字资产候选池：自动采集结果先入池，人工确认后经既有两段式导入落名单。
// 对账语义：入池时已存在于 digital_assets 的条目直接标 imported（batch_id 空）；
// rejected 是用户终态，重复入池只刷新证据字段，不改状态。

type DigitalCandidate struct {
	ID         int64     `json:"id"`
	ProjectID  int64     `json:"project_id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Company    string    `json:"company"`
	Platform   string    `json:"platform"`
	Source     string    `json:"source"`
	EntityName string    `json:"entity_name"`
	Evidence   string    `json:"evidence"`
	Status     string    `json:"status"`
	BatchID    *int64    `json:"batch_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type DigitalCandidateInput struct {
	Kind       string
	Name       string
	Company    string
	Platform   string
	Source     string
	EntityName string
	Evidence   string
}

type DigitalCandidateFilter struct {
	ProjectID int64
	Kind      string
	Status    string
	Query     string
	Page      int
	PageSize  int
}

type DigitalCandidateRepo interface {
	// UpsertCandidates 逐条入池，返回（新入池候选数, 直接入名单数）。
	// 已存在的行只刷新证据字段，状态与计数都不变（xmax=0 区分插入与更新）。
	UpsertCandidates(ctx context.Context, projectID int64, items []DigitalCandidateInput, existing func(kind, name string) bool) (int64, int64, error)
	ListCandidates(ctx context.Context, f DigitalCandidateFilter) ([]*DigitalCandidate, int64, error)
	CandidatesByIDs(ctx context.Context, projectID int64, ids []int64) ([]*DigitalCandidate, error)
	ConfirmCandidates(ctx context.Context, projectID int64, ids []int64, batchID int64) (int64, error)
	RejectCandidates(ctx context.Context, ids []int64) (int64, error)
}

type digitalCandidateRepo struct{ r *Repo }

func (r *Repo) DigitalCandidates() DigitalCandidateRepo { return &digitalCandidateRepo{r: r} }

func (r *digitalCandidateRepo) UpsertCandidates(ctx context.Context, projectID int64, items []DigitalCandidateInput, existing func(kind, name string) bool) (int64, int64, error) {
	var candidates, imported int64
	for _, a := range items {
		status := "candidate"
		if existing != nil && existing(a.Kind, a.Name) {
			status = "imported"
		}
		rows, err := r.r.pool.Query(ctx, `
insert into digital_candidates
    (project_id, kind, name, company, platform, source, entity_name, evidence, status)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
on conflict (project_id, kind, name) do update set
    company = excluded.company, platform = excluded.platform,
    source = excluded.source, entity_name = excluded.entity_name,
    evidence = excluded.evidence, updated_at = now()
returning status, (xmax = 0) as inserted`, projectID, a.Kind, a.Name, a.Company, a.Platform,
			a.Source, a.EntityName, a.Evidence, status)
		if err != nil {
			return 0, 0, err
		}
		for rows.Next() {
			var st string
			var inserted bool
			if err := rows.Scan(&st, &inserted); err != nil {
				rows.Close()
				return 0, 0, err
			}
			if !inserted {
				continue
			}
			if st == "imported" {
				imported++
			} else {
				candidates++
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return 0, 0, err
		}
		rows.Close()
	}
	return candidates, imported, nil
}

func (r *digitalCandidateRepo) ListCandidates(ctx context.Context, f DigitalCandidateFilter) ([]*DigitalCandidate, int64, error) {
	page, pageSize := vulnPage(f.Page, f.PageSize)
	w := newWhereBuilder(1)
	if f.ProjectID > 0 {
		w.parts = append(w.parts, "project_id = "+w.ph())
		w.args = append(w.args, f.ProjectID)
	}
	if s := strings.TrimSpace(f.Kind); s != "" {
		w.parts = append(w.parts, "kind = "+w.ph())
		w.args = append(w.args, s)
	}
	if s := strings.TrimSpace(f.Status); s != "" {
		w.parts = append(w.parts, "status = "+w.ph())
		w.args = append(w.args, s)
	}
	if s := strings.TrimSpace(f.Query); s != "" {
		w.parts = append(w.parts, "(name ilike "+w.ph()+" or company ilike "+w.ph()+
			" or entity_name ilike "+w.ph()+" or platform ilike "+w.ph()+")")
		like := "%" + s + "%"
		w.args = append(w.args, like, like, like, like)
	}
	cond := w.String()

	var total int64
	if err := r.r.pool.QueryRow(ctx,
		`select count(*) from digital_candidates where `+cond, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args := append(append([]any{}, w.args...), pageSize, (page-1)*pageSize)
	rows, err := r.r.pool.Query(ctx, fmt.Sprintf(`
select id, project_id, kind, name, company, platform, source, entity_name,
       evidence, status, batch_id, created_at, updated_at
  from digital_candidates
 where %s
 order by case status when 'candidate' then 0 else 1 end, id desc
 limit $%d offset $%d`, cond, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*DigitalCandidate{}
	for rows.Next() {
		c, err := scanCandidate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (r *digitalCandidateRepo) CandidatesByIDs(ctx context.Context, projectID int64, ids []int64) ([]*DigitalCandidate, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.r.pool.Query(ctx, `
select id, project_id, kind, name, company, platform, source, entity_name,
       evidence, status, batch_id, created_at, updated_at
  from digital_candidates
 where project_id = $1 and id = any($2)`, projectID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DigitalCandidate{}
	for rows.Next() {
		c, err := scanCandidate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *digitalCandidateRepo) ConfirmCandidates(ctx context.Context, projectID int64, ids []int64, batchID int64) (int64, error) {
	tag, err := r.r.pool.Exec(ctx, `
update digital_candidates
   set status = 'imported', batch_id = $3, updated_at = now()
 where project_id = $1 and status = 'candidate' and id = any($2)`,
		projectID, ids, batchID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *digitalCandidateRepo) RejectCandidates(ctx context.Context, ids []int64) (int64, error) {
	tag, err := r.r.pool.Exec(ctx, `
update digital_candidates
   set status = 'rejected', batch_id = null, updated_at = now()
 where status = 'candidate' and id = any($1)`, ids)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanCandidate(rs rowScanner) (*DigitalCandidate, error) {
	var (
		c         DigitalCandidate
		createdAt time.Time
		updatedAt time.Time
	)
	if err := rs.Scan(&c.ID, &c.ProjectID, &c.Kind, &c.Name, &c.Company, &c.Platform,
		&c.Source, &c.EntityName, &c.Evidence, &c.Status, &c.BatchID, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	c.CreatedAt = timeFromPG(&createdAt)
	c.UpdatedAt = timeFromPG(&updatedAt)
	return &c, nil
}
