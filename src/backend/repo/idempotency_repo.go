package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// 写操作幂等记录。
type IdempotencyRecord struct {
	Key         string
	UserID      string
	Method      string
	Path        string
	Status      int
	ContentType string
	Body        []byte
	Processing  bool
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

type IdempotencyRepo interface {
	// Reserve 尝试占位；reserved=false 时返回已有记录（可能仍在处理中）。
	Reserve(ctx context.Context, key, userID, method, path string, ttl time.Duration) (*IdempotencyRecord, bool, error)
	Complete(ctx context.Context, key string, status int, contentType string, body []byte) error
	Release(ctx context.Context, key string) error
}

type idempotencyRepo struct{ r *Repo }

func (r *Repo) Idempotency() IdempotencyRepo { return &idempotencyRepo{r: r} }

func (r *idempotencyRepo) Reserve(ctx context.Context, key, userID, method, path string, ttl time.Duration) (*IdempotencyRecord, bool, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	// 顺带清理过期记录，避免表无限增长。
	if _, err := tx.Exec(ctx, `delete from idempotency_keys where expires_at < now()`); err != nil {
		return nil, false, err
	}
	var (
		rec IdempotencyRecord
	)
	err = tx.QueryRow(ctx, `
insert into idempotency_keys (key, user_id, method, path, expires_at)
values ($1,$2,$3,$4,$5)
on conflict (key) do nothing
returning key, user_id, method, path, status, content_type, body, processing, created_at, expires_at`,
		key, userID, method, path, time.Now().Add(ttl),
	).Scan(&rec.Key, &rec.UserID, &rec.Method, &rec.Path, &rec.Status, &rec.ContentType,
		&rec.Body, &rec.Processing, &rec.CreatedAt, &rec.ExpiresAt)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return &rec, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	// 已被占用：读取现有记录。
	if err := tx.QueryRow(ctx, `
select key, user_id, method, path, status, content_type, body, processing, created_at, expires_at
  from idempotency_keys where key=$1`, key).
		Scan(&rec.Key, &rec.UserID, &rec.Method, &rec.Path, &rec.Status, &rec.ContentType,
			&rec.Body, &rec.Processing, &rec.CreatedAt, &rec.ExpiresAt); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return &rec, false, nil
}

func (r *idempotencyRepo) Complete(ctx context.Context, key string, status int, contentType string, body []byte) error {
	if contentType == "" {
		contentType = "application/json"
	}
	_, err := r.r.pool.Exec(ctx, `
update idempotency_keys
   set status=$2, content_type=$3, body=$4, processing=false
 where key=$1`, key, status, contentType, body)
	return err
}

func (r *idempotencyRepo) Release(ctx context.Context, key string) error {
	_, err := r.r.pool.Exec(ctx, `delete from idempotency_keys where key=$1`, key)
	return err
}
