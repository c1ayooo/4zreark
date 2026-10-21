package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// 项目生命周期：采集态汇总与永久删除。
//
// 删除是物理删除，依赖 schema 的 ON DELETE CASCADE 清掉站点、原始记录、
// 种子、计划、批次与执行单元；删除前先把各表行数记下来，审计里能回答
// 「这次删掉了多少东西」。

// ErrProjectConfirm 表示永久删除时 confirm_code 与项目编码不一致。
var ErrProjectConfirm = errors.New("项目确认码不正确")

// ProjectCollectionState 是项目采集态快照。
type ProjectCollectionState struct {
	ProjectID         int64      `json:"project_id"`
	Code              string     `json:"code"`
	Name              string     `json:"name"`
	Paused            bool       `json:"collection_paused"`
	PauseReason       string     `json:"collection_pause_reason"`
	CycleIntervalDays int        `json:"cycle_interval_days"`
	Sites             int64      `json:"sites"`
	Reachable         int64      `json:"reachable"`
	Lost              int64      `json:"lost"`
	Pending           int64      `json:"pending"`
	Archived          int64      `json:"archived"`
	Records           int64      `json:"records"`
	Endpoints         int64      `json:"endpoints"`
	Seeds             int64      `json:"seeds"`
	EnabledSeeds      int64      `json:"enabled_seeds"`
	Plans             int64      `json:"plans"`
	EnabledPlans      int64      `json:"enabled_plans"`
	Runs              int64      `json:"runs"`
	OpenRuns          int64      `json:"open_runs"`
	LastRunAt         *time.Time `json:"last_run_at"`
	NextRunAt         *time.Time `json:"next_run_at"`
	LastRecordAt      *time.Time `json:"last_record_at"`
}

// GetProjectCollectionState 取一个项目的采集态快照。
func (a *AssetRepo) GetProjectCollectionState(ctx context.Context, id int64) (*ProjectCollectionState, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	var s ProjectCollectionState
	err := a.r.pool.QueryRow(ctx, `
		SELECT p.id, p.code, p.name, p.collection_paused, coalesce(p.collection_pause_reason,''),
		       p.cycle_interval_days,
		       (SELECT count(*) FROM sites x WHERE x.project_id = p.id),
		       (SELECT count(*) FROM sites x WHERE x.project_id = p.id AND x.state = 'reachable'),
		       (SELECT count(*) FROM sites x WHERE x.project_id = p.id AND x.state = 'lost'),
		       (SELECT count(*) FROM sites x WHERE x.project_id = p.id AND x.state = 'pending'),
		       (SELECT count(*) FROM sites x WHERE x.project_id = p.id AND x.state = 'archived'),
		       (SELECT count(*) FROM raw_records x WHERE x.project_id = p.id),
		       (SELECT count(*) FROM site_endpoints e JOIN sites x ON x.id = e.site_id WHERE x.project_id = p.id),
		       (SELECT count(*) FROM seeds x WHERE x.project_id = p.id),
		       (SELECT count(*) FROM seeds x WHERE x.project_id = p.id AND x.enabled),
		       (SELECT count(*) FROM monitoring_plans mp JOIN seeds x ON x.id = mp.seed_id WHERE x.project_id = p.id),
		       (SELECT count(*) FROM monitoring_plans mp JOIN seeds x ON x.id = mp.seed_id
		         WHERE x.project_id = p.id AND mp.enabled),
		       (SELECT count(*) FROM runs x WHERE x.project_id = p.id),
		       (SELECT count(*) FROM runs x WHERE x.project_id = p.id AND x.status IN ('queued','running')),
		       (SELECT max(x.cycle_start) FROM runs x WHERE x.project_id = p.id),
		       (SELECT min(mp.next_run_at) FROM monitoring_plans mp JOIN seeds x ON x.id = mp.seed_id
		         WHERE x.project_id = p.id AND mp.enabled),
		       (SELECT max(x.observed_at) FROM raw_records x WHERE x.project_id = p.id)
		  FROM projects p
		 WHERE p.id = $1`, id).
		Scan(&s.ProjectID, &s.Code, &s.Name, &s.Paused, &s.PauseReason, &s.CycleIntervalDays,
			&s.Sites, &s.Reachable, &s.Lost, &s.Pending, &s.Archived, &s.Records, &s.Endpoints,
			&s.Seeds, &s.EnabledSeeds, &s.Plans, &s.EnabledPlans, &s.Runs, &s.OpenRuns,
			&s.LastRunAt, &s.NextRunAt, &s.LastRecordAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ProjectDeleteResult 是永久删除的回执：删掉了哪些规模的数据。
type ProjectDeleteResult struct {
	ProjectID int64  `json:"project_id"`
	Code      string `json:"code"`
	Name      string `json:"name"`
	Sites     int64  `json:"sites"`
	Records   int64  `json:"records"`
	Endpoints int64  `json:"endpoints"`
	Seeds     int64  `json:"seeds"`
	Plans     int64  `json:"plans"`
	Runs      int64  `json:"runs"`
	Targets   int64  `json:"run_targets"`
}

// DeleteProject 永久删除项目。confirmCode 必须与项目编码完全一致。
func (a *AssetRepo) DeleteProject(ctx context.Context, id int64, confirmCode string) (*ProjectDeleteResult, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	tx, err := a.r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	res := &ProjectDeleteResult{ProjectID: id}
	if err := tx.QueryRow(ctx,
		`SELECT code, name FROM projects WHERE id = $1 FOR UPDATE`, id).
		Scan(&res.Code, &res.Name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if confirmCode != res.Code {
		return nil, ErrProjectConfirm
	}

	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM sites WHERE project_id = $1),
		       (SELECT count(*) FROM raw_records WHERE project_id = $1),
		       (SELECT count(*) FROM site_endpoints e JOIN sites s ON s.id = e.site_id WHERE s.project_id = $1),
		       (SELECT count(*) FROM seeds WHERE project_id = $1),
		       (SELECT count(*) FROM monitoring_plans mp JOIN seeds s ON s.id = mp.seed_id WHERE s.project_id = $1),
		       (SELECT count(*) FROM runs WHERE project_id = $1),
		       (SELECT count(*) FROM run_targets t JOIN runs r ON r.id = t.run_id WHERE r.project_id = $1)`, id).
		Scan(&res.Sites, &res.Records, &res.Endpoints, &res.Seeds, &res.Plans, &res.Runs, &res.Targets); err != nil {
		return nil, err
	}

	// import_batches 没有外键（沿用 v4 DDL），项目删除时显式清掉，避免回执成孤儿。
	if _, err := tx.Exec(ctx, `DELETE FROM import_batches WHERE project_id = $1`, id); err != nil {
		return nil, fmt.Errorf("清理导入回执失败: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id); err != nil {
		return nil, fmt.Errorf("删除项目失败: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// SetProjectIcon 把项目图标指向 asset_icons 里的内容哈希。
func (a *AssetRepo) SetProjectIcon(ctx context.Context, id int64, sha256 string) error {
	if a == nil || a.r == nil {
		return errUninitialized()
	}
	tag, err := a.r.pool.Exec(ctx,
		`UPDATE projects SET icon_sha256 = $2, updated_at = now() WHERE id = $1`, id, sha256)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearProjectIcon 清空项目图标引用（图标字节本身按哈希保留）。
func (a *AssetRepo) ClearProjectIcon(ctx context.Context, id int64) error {
	return a.SetProjectIcon(ctx, id, "")
}

// ProjectOption 是下拉选择用的项目摘要。
type ProjectOption struct {
	ID   int64  `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}

func (a *AssetRepo) ListProjectOptions(ctx context.Context) ([]*ProjectOption, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	rows, err := a.r.pool.Query(ctx, `SELECT id, code, name FROM projects ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProjectOption{}
	for rows.Next() {
		var o ProjectOption
		if err := rows.Scan(&o.ID, &o.Code, &o.Name); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	return out, rows.Err()
}

// ProjectStats 是项目/资产规模的总览口径。
type ProjectStats struct {
	Projects int64 `json:"projects"`
	Sites    int64 `json:"sites"`
	Records  int64 `json:"records"`
	Lost     int64 `json:"lost"`
	NewToday int64 `json:"new_today"`
}

func (a *AssetRepo) ProjectStats(ctx context.Context) (*ProjectStats, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	st := &ProjectStats{}
	err := a.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM projects),
		       (SELECT count(*) FROM sites),
		       (SELECT count(*) FROM raw_records),
		       (SELECT count(*) FROM sites WHERE state = 'lost'),
		       (SELECT count(*) FROM sites WHERE first_seen >= current_date)`).
		Scan(&st.Projects, &st.Sites, &st.Records, &st.Lost, &st.NewToday)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// ProjectCycleStatus 是调度侧的健康快照。
type ProjectCycleStatus struct {
	DuePlans       int64      `json:"due_plans"`
	PausedProjects int64      `json:"paused_projects"`
	OpenRuns       int64      `json:"open_runs"`
	PendingTargets int64      `json:"pending_targets"`
	LastRunAt      *time.Time `json:"last_run_at"`
}

func (a *AssetRepo) ProjectCycleStatus(ctx context.Context) (*ProjectCycleStatus, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	st := &ProjectCycleStatus{}
	err := a.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM monitoring_plans mp
		          JOIN seeds se ON se.id = mp.seed_id
		          JOIN projects p ON p.id = se.project_id
		         WHERE mp.enabled AND mp.next_run_at <= now() AND NOT p.collection_paused),
		       (SELECT count(*) FROM projects WHERE collection_paused),
		       (SELECT count(*) FROM runs WHERE status IN ('queued','running')),
		       (SELECT count(*) FROM run_targets WHERE state IN ('pending','running')),
		       (SELECT max(cycle_start) FROM runs)`).
		Scan(&st.DuePlans, &st.PausedProjects, &st.OpenRuns, &st.PendingTargets, &st.LastRunAt)
	if err != nil {
		return nil, err
	}
	return st, nil
}
