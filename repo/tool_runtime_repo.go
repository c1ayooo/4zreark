package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/c1ayooo/4zreark/internal/toolruntime"
)

// ToolRuntimeRepo 是 tool_runtime / tool_update_history 两张表的 pgx 实现，
// 满足 toolruntime.Store 接口。
type ToolRuntimeRepo interface {
	LoadState(ctx context.Context, name string) (*toolruntime.ToolState, error)
	SaveState(ctx context.Context, st *toolruntime.ToolState) error
	AppendRecord(ctx context.Context, rec toolruntime.UpdateRecord) error
	ListRecords(ctx context.Context, name string, limit int) ([]toolruntime.UpdateRecord, error)
}

type toolRuntimeRepo struct{ r *Repo }

func (r *Repo) ToolRuntime() ToolRuntimeRepo { return &toolRuntimeRepo{r: r} }

func (r *toolRuntimeRepo) LoadState(ctx context.Context, name string) (*toolruntime.ToolState, error) {
	st := &toolruntime.ToolState{}
	err := r.r.pool.QueryRow(ctx, `
select name, repo, pinned_version, installed_version, installed_sha256,
       prev_version, prev_sha256, latest_version, latest_checked_at,
       auto_update, check_interval_hours, status, status_note, updated_at
from tool_runtime where name=$1`, name).Scan(
		&st.Name, &st.Repo, &st.PinnedVersion, &st.InstalledVersion, &st.InstalledSHA256,
		&st.PrevVersion, &st.PrevSHA256, &st.LatestVersion, &st.LatestCheckedAt,
		&st.AutoUpdate, &st.CheckIntervalHours, &st.Status, &st.StatusNote, &st.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (r *toolRuntimeRepo) SaveState(ctx context.Context, st *toolruntime.ToolState) error {
	_, err := r.r.pool.Exec(ctx, `
insert into tool_runtime (name, repo, pinned_version, installed_version, installed_sha256,
                          prev_version, prev_sha256, latest_version, latest_checked_at,
                          auto_update, check_interval_hours, status, status_note, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())
on conflict (name) do update set
    repo = excluded.repo,
    pinned_version = excluded.pinned_version,
    installed_version = excluded.installed_version,
    installed_sha256 = excluded.installed_sha256,
    prev_version = excluded.prev_version,
    prev_sha256 = excluded.prev_sha256,
    latest_version = excluded.latest_version,
    latest_checked_at = excluded.latest_checked_at,
    auto_update = excluded.auto_update,
    check_interval_hours = excluded.check_interval_hours,
    status = excluded.status,
    status_note = excluded.status_note,
    updated_at = now()`,
		st.Name, st.Repo, st.PinnedVersion, st.InstalledVersion, st.InstalledSHA256,
		st.PrevVersion, st.PrevSHA256, st.LatestVersion, st.LatestCheckedAt,
		st.AutoUpdate, st.CheckIntervalHours, st.Status, st.StatusNote)
	return err
}

func (r *toolRuntimeRepo) AppendRecord(ctx context.Context, rec toolruntime.UpdateRecord) error {
	_, err := r.r.pool.Exec(ctx, `
insert into tool_update_history (tool, from_version, to_version, sha256, ok, note)
values ($1,$2,$3,$4,$5,$6)`,
		rec.Tool, rec.FromVersion, rec.ToVersion, rec.SHA256, rec.OK, rec.Note)
	return err
}

func (r *toolRuntimeRepo) ListRecords(ctx context.Context, name string, limit int) ([]toolruntime.UpdateRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := r.r.pool.Query(ctx, `
select tool, from_version, to_version, sha256, ok, note, created_at
from tool_update_history where tool=$1
order by created_at desc limit $2`, name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []toolruntime.UpdateRecord
	for rows.Next() {
		var rec toolruntime.UpdateRecord
		if err := rows.Scan(&rec.Tool, &rec.FromVersion, &rec.ToVersion, &rec.SHA256,
			&rec.OK, &rec.Note, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
