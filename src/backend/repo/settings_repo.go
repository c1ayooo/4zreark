package repo

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// 系统单例设置（app_settings 单行 JSON）。
type SettingsRepo interface {
	Get(ctx context.Context, key string, out any) (bool, error)
	Set(ctx context.Context, key string, value any) error
	Delete(ctx context.Context, key string) error
}

type settingsRepo struct{ r *Repo }

func (r *Repo) Settings() SettingsRepo { return &settingsRepo{r: r} }

func (r *settingsRepo) Get(ctx context.Context, key string, out any) (bool, error) {
	var raw []byte
	err := r.r.pool.QueryRow(ctx, `select value from app_settings where key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, err
	}
	return true, nil
}

func (r *settingsRepo) Set(ctx context.Context, key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = r.r.pool.Exec(ctx, `
insert into app_settings (key, value, updated_at)
values ($1,$2::jsonb, now())
on conflict (key) do update set value = excluded.value, updated_at = now()`, key, string(b))
	return err
}

func (r *settingsRepo) Delete(ctx context.Context, key string) error {
	_, err := r.r.pool.Exec(ctx, `delete from app_settings where key=$1`, key)
	return err
}
