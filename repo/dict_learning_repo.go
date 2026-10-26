package repo

import (
	"context"
	"sync"
	"time"
)

// 字典自学习：子域首标签 / 接口路径在任务中的出现频次达到阈值后晋升进词表。
//
// 计频口径：每次 RecordBatch（每任务一批，批内去重）hits+1，即 hits =
// 观察到该值的任务数。denied 的行不再计频、不再晋升（人工剔除）。
// 晋升只打 promoted_at 时间戳，词表合并由派单物化（task_dictionary.go）完成。

const (
	DictKindSubdomain = "subdomain"
	DictKindPath      = "path"
)

// DictLearningEntry 是一条学习条目。
type DictLearningEntry struct {
	ID         int64      `json:"id"`
	Kind       string     `json:"kind"`
	Value      string     `json:"value"`
	Hits       int        `json:"hits"`
	Denied     bool       `json:"denied"`
	PromotedAt *time.Time `json:"promoted_at,omitempty"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	LastProjID int64      `json:"last_project_id"`
}

type DictLearningRepo interface {
	// RecordBatch 批量计频（批内值应已去重）并按阈值晋升，返回本轮新晋升条数。
	RecordBatch(ctx context.Context, kind string, values []string, projectID int64, promoteThreshold int) (int, error)
	// List 分页列出学习条目；kind 为空返回全部。
	List(ctx context.Context, kind string, limit, offset int) ([]*DictLearningEntry, int64, error)
	// SetDenied 人工剔除/恢复。剔除后不再计频不再晋升，也不进词表。
	SetDenied(ctx context.Context, id int64, denied bool) error
	// PromotedValues 已晋升且未被剔除的热词，按频次倒序。
	PromotedValues(ctx context.Context, kind string, max int) ([]string, error)
	// CountByKind 按类型统计（未剔除）。
	CountByKind(ctx context.Context, kind string) (int64, error)
}

type dictLearningRepo struct{ r *Repo }

func (r *Repo) DictLearning() DictLearningRepo { return &dictLearningRepo{r: r} }

var dictLearningSchemaOnce sync.Once

func (d *dictLearningRepo) ensureSchema(ctx context.Context) error {
	var err error
	dictLearningSchemaOnce.Do(func() {
		_, err = d.r.pool.Exec(ctx, `
create table if not exists dict_learning (
	id bigserial primary key,
	kind text not null,
	value text not null,
	hits int not null default 1,
	denied boolean not null default false,
	promoted_at timestamptz,
	first_seen timestamptz not null default now(),
	last_seen timestamptz not null default now(),
	last_project_id bigint not null default 0,
	unique (kind, value)
);
create index if not exists idx_dict_learning_kind_hits on dict_learning (kind, hits desc);`)
		if err != nil {
			dictLearningSchemaOnce = sync.Once{}
		}
	})
	return err
}

func (d *dictLearningRepo) RecordBatch(ctx context.Context, kind string, values []string, projectID int64, promoteThreshold int) (int, error) {
	if d.r == nil || len(values) == 0 {
		return 0, nil
	}
	if err := d.ensureSchema(ctx); err != nil {
		return 0, err
	}
	if promoteThreshold < 1 {
		promoteThreshold = 1
	}
	// denied 行被 WHERE 挡住不计频；新值照常插入。
	_, err := d.r.pool.Exec(ctx, `
insert into dict_learning (kind, value, last_project_id)
select $1, v, $3 from unnest($2::text[]) v
on conflict (kind, value) do update set
	hits = dict_learning.hits + 1,
	last_seen = now(),
	last_project_id = excluded.last_project_id
where not dict_learning.denied`, kind, values, projectID)
	if err != nil {
		return 0, err
	}
	var promoted int
	err = d.r.pool.QueryRow(ctx, `
with t as (
	update dict_learning set promoted_at = now()
	 where kind = $1 and not denied and promoted_at is null and hits >= $2
	returning 1)
select count(*) from t`, kind, promoteThreshold).Scan(&promoted)
	return promoted, err
}

func (d *dictLearningRepo) List(ctx context.Context, kind string, limit, offset int) ([]*DictLearningEntry, int64, error) {
	if d.r == nil {
		return nil, 0, errUninitialized()
	}
	if err := d.ensureSchema(ctx); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var total int64
	if err := d.r.pool.QueryRow(ctx,
		`select count(*) from dict_learning where ($1 = '' or kind = $1)`, kind).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.r.pool.Query(ctx, `
select id, kind, value, hits, denied, promoted_at, first_seen, last_seen, last_project_id
  from dict_learning
 where ($1 = '' or kind = $1)
 order by hits desc, last_seen desc, id desc
 limit $2 offset $3`, kind, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*DictLearningEntry{}
	for rows.Next() {
		var e DictLearningEntry
		if err := rows.Scan(&e.ID, &e.Kind, &e.Value, &e.Hits, &e.Denied, &e.PromotedAt,
			&e.FirstSeen, &e.LastSeen, &e.LastProjID); err != nil {
			return nil, 0, err
		}
		out = append(out, &e)
	}
	return out, total, rows.Err()
}

func (d *dictLearningRepo) SetDenied(ctx context.Context, id int64, denied bool) error {
	if d.r == nil {
		return errUninitialized()
	}
	if err := d.ensureSchema(ctx); err != nil {
		return err
	}
	tag, err := d.r.pool.Exec(ctx,
		`update dict_learning set denied = $2 where id = $1`, id, denied)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// promoted_at 保留不动：词表合并与计频都按 not denied 过滤，
	// 恢复后已晋升的词立即回到词表，未晋升的按原频次继续竞争。
	return nil
}

func (d *dictLearningRepo) PromotedValues(ctx context.Context, kind string, max int) ([]string, error) {
	if d.r == nil {
		return nil, errUninitialized()
	}
	if err := d.ensureSchema(ctx); err != nil {
		return nil, err
	}
	if max <= 0 || max > 2000 {
		max = 300
	}
	rows, err := d.r.pool.Query(ctx, `
select value from dict_learning
 where kind = $1 and not denied and promoted_at is not null
 order by hits desc, last_seen desc
 limit $2`, kind, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (d *dictLearningRepo) CountByKind(ctx context.Context, kind string) (int64, error) {
	if d.r == nil {
		return 0, errUninitialized()
	}
	if err := d.ensureSchema(ctx); err != nil {
		return 0, err
	}
	var n int64
	err := d.r.pool.QueryRow(ctx,
		`select count(*) from dict_learning where kind = $1 and not denied`, kind).Scan(&n)
	return n, err
}
