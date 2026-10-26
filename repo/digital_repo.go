package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 数字资产（APP/小程序/公众号/新媒体）与导入回执。与站点库解耦：
// 这里只登记名单，不创建站点、不触发 DNS 与验证。

type DigitalAsset struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Company   string    `json:"company"`
	Platform  string    `json:"platform"`
	Source    string    `json:"source"`
	Status    string    `json:"status"`
	BatchID   *int64    `json:"batch_id"`
	CreatedAt time.Time `json:"created_at"`
}

type DigitalAssetInput struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Company  string `json:"company"`
	Platform string `json:"platform"`
	Source   string `json:"source"`
}

type DigitalFilter struct {
	ProjectID int64
	Kind      string
	Query     string
	Page      int
	PageSize  int
}

type ImportBatch struct {
	ID        int64          `json:"id"`
	ProjectID int64          `json:"project_id"`
	Kind      string         `json:"kind"`
	Status    string         `json:"status"`
	Summary   map[string]any `json:"summary"`
	CreatedBy string         `json:"created_by"`
	CreatedAt time.Time      `json:"created_at"`
}

type DigitalRepo interface {
	List(ctx context.Context, f DigitalFilter) ([]*DigitalAsset, int64, error)
	Delete(ctx context.Context, id int64) (bool, error)
	ExistingNames(ctx context.Context, projectID int64, kind string, names []string) (map[string]bool, error)
	// InsertBatch 在一个事务里写回执 + 名单；重复项按 (project,kind,name) 忽略。
	InsertBatch(ctx context.Context, projectID int64, batchKind string, assets []DigitalAssetInput, summary map[string]any, createdBy string) (*ImportBatch, int64, error)
	// UndoBatch 只回滚该批次新增的名单，已存在的记录不动。
	UndoBatch(ctx context.Context, batchID int64) (int64, error)
	ListBatches(ctx context.Context, projectID int64, limit int) ([]*ImportBatch, error)
}

type digitalRepo struct{ r *Repo }

func (r *Repo) Digital() DigitalRepo { return &digitalRepo{r: r} }

func (r *digitalRepo) List(ctx context.Context, f DigitalFilter) ([]*DigitalAsset, int64, error) {
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
	if s := strings.TrimSpace(f.Query); s != "" {
		w.parts = append(w.parts, "(name ilike "+w.ph()+" or company ilike "+w.ph()+" or platform ilike "+w.ph()+")")
		like := "%" + s + "%"
		w.args = append(w.args, like, like, like)
	}
	cond := w.String()

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from digital_assets where `+cond, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args := append(append([]any{}, w.args...), pageSize, (page-1)*pageSize)
	rows, err := r.r.pool.Query(ctx, fmt.Sprintf(`
select id, project_id, kind, name, company, platform, source, status, batch_id, created_at
  from digital_assets
 where %s
 order by id desc
 limit $%d offset $%d`, cond, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*DigitalAsset{}
	for rows.Next() {
		var (
			a         DigitalAsset
			createdAt time.Time
		)
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Kind, &a.Name, &a.Company,
			&a.Platform, &a.Source, &a.Status, &a.BatchID, &createdAt); err != nil {
			return nil, 0, err
		}
		a.CreatedAt = timeFromPG(&createdAt)
		out = append(out, &a)
	}
	return out, total, rows.Err()
}

func (r *digitalRepo) Delete(ctx context.Context, id int64) (bool, error) {
	tag, err := r.r.pool.Exec(ctx, `delete from digital_assets where id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *digitalRepo) ExistingNames(ctx context.Context, projectID int64, kind string, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(names) == 0 {
		return out, nil
	}
	rows, err := r.r.pool.Query(ctx,
		`select name from digital_assets where project_id = $1 and kind = $2 and name = any($3)`,
		projectID, kind, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func (r *digitalRepo) InsertBatch(ctx context.Context, projectID int64, batchKind string, assets []DigitalAssetInput, summary map[string]any, createdBy string) (*ImportBatch, int64, error) {
	if len(assets) == 0 {
		return nil, 0, errors.New("没有可导入的名单")
	}
	if summary == nil {
		summary = map[string]any{}
	}
	summaryB, err := json.Marshal(summary)
	if err != nil {
		return nil, 0, fmt.Errorf("序列化导入摘要失败: %w", err)
	}
	var createdByVal any
	if s := strings.TrimSpace(createdBy); s != "" {
		createdByVal = s
	}

	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback(ctx)

	var batch ImportBatch
	var summaryOut []byte
	if err := tx.QueryRow(ctx, `
insert into import_batches (project_id, kind, status, summary, created_by)
values ($1,$2,'committed',$3::jsonb,$4)
returning id, project_id, kind, status, summary, created_at`,
		projectID, batchKind, string(summaryB), createdByVal,
	).Scan(&batch.ID, &batch.ProjectID, &batch.Kind, &batch.Status, &summaryOut, &batch.CreatedAt); err != nil {
		return nil, 0, err
	}
	_ = json.Unmarshal(summaryOut, &batch.Summary)
	batch.CreatedBy = createdBy

	var inserted int64
	for _, a := range assets {
		tag, err := tx.Exec(ctx, `
insert into digital_assets (project_id, kind, name, company, platform, source, status, batch_id)
values ($1,$2,$3,$4,$5,$6,'unverified',$7)
on conflict (project_id, kind, name) do nothing`,
			projectID, a.Kind, a.Name, a.Company, a.Platform, a.Source, batch.ID)
		if err != nil {
			return nil, 0, err
		}
		inserted += tag.RowsAffected()
	}
	if _, err := tx.Exec(ctx,
		`update import_batches
		    set summary = summary || jsonb_build_object('inserted', $1::int, 'duplicates', $2::int)
		  where id = $3`, inserted, int64(len(assets))-inserted, batch.ID); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	batch.Summary["inserted"] = inserted
	batch.Summary["duplicates"] = int64(len(assets)) - inserted
	return &batch, inserted, nil
}

func (r *digitalRepo) UndoBatch(ctx context.Context, batchID int64) (int64, error) {
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `delete from digital_assets where batch_id = $1`, batchID)
	if err != nil {
		return 0, err
	}
	deleted := tag.RowsAffected()
	// 名单行已随批次删除的候选回退为待确认；名单行仍在的（经其它路径导入）
	// 保持 imported，只清批次引用。
	if _, err := tx.Exec(ctx, `
update digital_candidates
   set status = 'candidate', batch_id = null, updated_at = now()
 where batch_id = $1 and status = 'imported'
   and not exists (select 1 from digital_assets da
                    where da.project_id = digital_candidates.project_id
                      and da.kind = digital_candidates.kind
                      and da.name = digital_candidates.name)`, batchID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
update digital_candidates
   set batch_id = null, updated_at = now()
 where batch_id = $1 and status = 'imported'`, batchID); err != nil {
		return 0, err
	}
	upd, err := tx.Exec(ctx,
		`update import_batches set status = 'undone' where id = $1 and status = 'committed'`, batchID)
	if err != nil {
		return 0, err
	}
	if upd.RowsAffected() == 0 {
		return 0, ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return deleted, nil
}

func (r *digitalRepo) ListBatches(ctx context.Context, projectID int64, limit int) ([]*ImportBatch, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `select id, project_id, kind, status, summary, coalesce(created_by, ''), created_at from import_batches`
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` where project_id = $1`
	}
	args = append(args, limit)
	q += fmt.Sprintf(` order by created_at desc, id desc limit $%d`, len(args))

	rows, err := r.r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ImportBatch{}
	for rows.Next() {
		var (
			b         ImportBatch
			summaryB  []byte
			createdAt time.Time
		)
		if err := rows.Scan(&b.ID, &b.ProjectID, &b.Kind, &b.Status, &summaryB, &b.CreatedBy, &createdAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(summaryB, &b.Summary)
		if b.Summary == nil {
			b.Summary = map[string]any{}
		}
		b.CreatedAt = timeFromPG(&createdAt)
		out = append(out, &b)
	}
	return out, rows.Err()
}
