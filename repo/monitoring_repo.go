package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// 监控预设与计划批量操作。
//
// 预设是「间隔 + 预算」的命名模板，`is_default` 全表最多一条；
// 批量操作只改 enabled / interval_hours，不动 seed 与历史 run。

type MonitoringPreset struct {
	ID            int64          `json:"id"`
	Name          string         `json:"name"`
	IntervalHours int            `json:"interval_hours"`
	Budget        map[string]any `json:"budget"`
	IsDefault     bool           `json:"is_default"`
	CreatedAt     time.Time      `json:"created_at"`
}

type MonitoringPresetInput struct {
	Name          string
	IntervalHours int
	Budget        map[string]any
	IsDefault     bool
}

const presetColumns = `id, name, interval_hours, budget, is_default, created_at`

func scanPreset(row pgx.Row) (*MonitoringPreset, error) {
	var p MonitoringPreset
	var budget []byte
	if err := row.Scan(&p.ID, &p.Name, &p.IntervalHours, &budget, &p.IsDefault, &p.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	if len(budget) > 0 {
		_ = json.Unmarshal(budget, &p.Budget)
	}
	if p.Budget == nil {
		p.Budget = map[string]any{}
	}
	return &p, nil
}

func (r *SeedOpsRepo) ListPresets(ctx context.Context) ([]*MonitoringPreset, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	rows, err := r.r.pool.Query(ctx,
		`SELECT `+presetColumns+` FROM monitoring_presets ORDER BY is_default DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*MonitoringPreset{}
	for rows.Next() {
		p, err := scanPreset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *SeedOpsRepo) DefaultPreset(ctx context.Context) (*MonitoringPreset, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	return scanPreset(r.r.pool.QueryRow(ctx,
		`SELECT `+presetColumns+` FROM monitoring_presets WHERE is_default LIMIT 1`))
}

func (r *SeedOpsRepo) CreatePreset(ctx context.Context, in MonitoringPresetInput) (*MonitoringPreset, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	budget, err := jsonb(in.Budget)
	if err != nil {
		return nil, err
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if in.IsDefault {
		if _, err := tx.Exec(ctx, `UPDATE monitoring_presets SET is_default = false WHERE is_default`); err != nil {
			return nil, err
		}
	}
	var id int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO monitoring_presets (name, interval_hours, budget, is_default)
		VALUES ($1,$2,$3,$4) RETURNING id`,
		in.Name, in.IntervalHours, budget, in.IsDefault).Scan(&id); err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("预设名 %q 已存在", in.Name)
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return scanPreset(r.r.pool.QueryRow(ctx, `SELECT `+presetColumns+` FROM monitoring_presets WHERE id = $1`, id))
}

func (r *SeedOpsRepo) UpdatePreset(ctx context.Context, id int64, in MonitoringPresetInput) (*MonitoringPreset, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	budget, err := jsonb(in.Budget)
	if err != nil {
		return nil, err
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if in.IsDefault {
		if _, err := tx.Exec(ctx, `UPDATE monitoring_presets SET is_default = false WHERE is_default AND id <> $1`, id); err != nil {
			return nil, err
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE monitoring_presets
		   SET name = $2, interval_hours = $3, budget = $4, is_default = $5
		 WHERE id = $1`, id, in.Name, in.IntervalHours, budget, in.IsDefault)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("预设名 %q 已存在", in.Name)
		}
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return scanPreset(r.r.pool.QueryRow(ctx, `SELECT `+presetColumns+` FROM monitoring_presets WHERE id = $1`, id))
}

func (r *SeedOpsRepo) DeletePreset(ctx context.Context, id int64) error {
	if r == nil || r.r == nil {
		return errUninitialized()
	}
	tag, err := r.r.pool.Exec(ctx, `DELETE FROM monitoring_presets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PlanBulkFilter 支持按计划 ID 或按项目筛选。
type PlanBulkFilter struct {
	PlanIDs   []int64
	ProjectID int64
}

func (f PlanBulkFilter) empty() bool { return len(f.PlanIDs) == 0 && f.ProjectID <= 0 }

func (f PlanBulkFilter) where(alias string) (string, []any) {
	args := []any{}
	where := " WHERE 1=1"
	if len(f.PlanIDs) > 0 {
		args = append(args, f.PlanIDs)
		where += fmt.Sprintf(" AND %s.id = ANY($%d)", alias, len(args))
	}
	if f.ProjectID > 0 {
		args = append(args, f.ProjectID)
		where += fmt.Sprintf(" AND s.project_id = $%d", len(args))
	}
	return where, args
}

const planBulkMax = 1000

// ListPlansForBulk 返回筛选命中的计划，最多 1000 条。
func (r *SeedOpsRepo) ListPlansForBulk(ctx context.Context, f PlanBulkFilter) ([]*Plan, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	if f.empty() {
		return nil, errors.New("plan_ids 与 project_id 至少提供一个")
	}
	where, args := f.where("p")
	if len(f.PlanIDs) > planBulkMax {
		return nil, fmt.Errorf("单次最多操作 %d 个计划", planBulkMax)
	}
	args = append(args, planBulkMax)
	rows, err := r.r.pool.Query(ctx,
		`SELECT `+planColumns+planFrom+where+fmt.Sprintf(` ORDER BY p.id LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Plan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// BulkUpdatePlans 批量启停/改间隔，nil 表示该字段不变。
func (r *SeedOpsRepo) BulkUpdatePlans(ctx context.Context, ids []int64, enabled *bool, intervalHours *int) (int64, error) {
	if r == nil || r.r == nil {
		return 0, errUninitialized()
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var enabledArg any
	if enabled != nil {
		enabledArg = *enabled
	}
	var intervalArg any
	if intervalHours != nil {
		intervalArg = *intervalHours
	}
	tag, err := r.r.pool.Exec(ctx, `
		UPDATE monitoring_plans
		   SET enabled = COALESCE($2, enabled),
		       interval_hours = COALESCE($3, interval_hours)
		 WHERE id = ANY($1)`, ids, enabledArg, intervalArg)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
