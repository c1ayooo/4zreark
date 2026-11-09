package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CollectionPlan 是信息收集阶段编排的父计划。
type CollectionPlan struct {
	ID           string
	ProjectID    int64
	Mode         string
	Status       string
	CurrentStage string
	Seed         string
	Deadline     *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CollectionStage 是计划下的单个阶段账本。
type CollectionStage struct {
	ID         int64
	PlanID     string
	Stage      string
	TaskID     string
	Status     string
	Attempt    int
	SkipReason string
	StartedAt  *time.Time
	FinishedAt *time.Time
}

// CollectionRepo 访问 collection_plans / collection_stages 与阶段产出。
type CollectionRepo struct {
	pool *pgxpool.Pool
}

// NewCollectionRepo 返回计划仓储；数据层未初始化时返回 nil。
func NewCollectionRepo() *CollectionRepo {
	r := Default()
	if r == nil || r.Pool() == nil {
		return nil
	}
	return &CollectionRepo{pool: r.Pool()}
}

func (r *CollectionRepo) CreatePlan(ctx context.Context, p *CollectionPlan) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	_, err := r.pool.Exec(ctx, `
		insert into collection_plans (id, project_id, mode, status, current_stage, seed, deadline, created_at, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7,now(),now())`,
		p.ID, p.ProjectID, p.Mode, p.Status, p.CurrentStage, p.Seed, p.Deadline)
	return err
}

func (r *CollectionRepo) GetPlan(ctx context.Context, id string) (*CollectionPlan, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	var p CollectionPlan
	var deadline *time.Time
	err := r.pool.QueryRow(ctx, `
		select id, project_id, mode, status, current_stage, seed, deadline, created_at, updated_at
		  from collection_plans where id = $1`, id).
		Scan(&p.ID, &p.ProjectID, &p.Mode, &p.Status, &p.CurrentStage, &p.Seed, &deadline, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	p.Deadline = deadline
	return &p, nil
}

// UpdatePlanProgress 只更新编排状态，不允许调用方改写计划身份字段。
func (r *CollectionRepo) UpdatePlanProgress(ctx context.Context, id, status, currentStage string) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	_, err := r.pool.Exec(ctx, `
		update collection_plans
		   set status = $2, current_stage = $3, updated_at = now()
		 where id = $1`, id, status, currentStage)
	return err
}

// UpsertStage 幂等创建阶段账本，返回阶段 ID。
func (r *CollectionRepo) UpsertStage(ctx context.Context, planID, stage string) (int64, error) {
	if r == nil || r.pool == nil {
		return 0, fmt.Errorf("数据层未初始化")
	}
	var id int64
	err := r.pool.QueryRow(ctx, `
		insert into collection_stages (plan_id, stage, status, updated_at)
		values ($1,$2,'pending',now())
		on conflict (plan_id, stage) do update set updated_at = now()
		returning id`, planID, stage).Scan(&id)
	return id, err
}

func (r *CollectionRepo) GetStage(ctx context.Context, planID, stage string) (*CollectionStage, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	var st CollectionStage
	var started, finished *time.Time
	err := r.pool.QueryRow(ctx, `
		select id, plan_id, stage, coalesce(task_id,''), status, attempt,
		       skip_reason, started_at, finished_at
		  from collection_stages where plan_id = $1 and stage = $2`, planID, stage).
		Scan(&st.ID, &st.PlanID, &st.Stage, &st.TaskID, &st.Status, &st.Attempt,
			&st.SkipReason, &started, &finished)
	if err != nil {
		return nil, err
	}
	st.StartedAt, st.FinishedAt = started, finished
	return &st, nil
}

func (r *CollectionRepo) ListStages(ctx context.Context, planID string) ([]*CollectionStage, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	rows, err := r.pool.Query(ctx, `
		select id, plan_id, stage, coalesce(task_id,''), status, attempt,
		       skip_reason, started_at, finished_at
		  from collection_stages where plan_id = $1 order by id`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CollectionStage
	for rows.Next() {
		var st CollectionStage
		var started, finished *time.Time
		if err := rows.Scan(&st.ID, &st.PlanID, &st.Stage, &st.TaskID, &st.Status, &st.Attempt,
			&st.SkipReason, &started, &finished); err != nil {
			return nil, err
		}
		st.StartedAt, st.FinishedAt = started, finished
		out = append(out, &st)
	}
	return out, rows.Err()
}

// MarkStageRunning 把阶段置为 running 并绑定子任务。
func (r *CollectionRepo) MarkStageRunning(ctx context.Context, id int64, taskID string) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	_, err := r.pool.Exec(ctx, `
		update collection_stages
		   set status = 'running', task_id = $2, attempt = attempt + 1,
		       started_at = coalesce(started_at, now()), updated_at = now()
		 where id = $1`, id, taskID)
	return err
}

// MarkStageTerminal 把阶段置为终态；跳过原因一并落库，避免“静默成功”。
func (r *CollectionRepo) MarkStageTerminal(ctx context.Context, id int64, status, skipReason string) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("数据层未初始化")
	}
	_, err := r.pool.Exec(ctx, `
		update collection_stages
		   set status = $2, skip_reason = $3, finished_at = now(), updated_at = now()
		 where id = $1`, id, status, skipReason)
	return err
}

// ListRunningPlans 给 reconciler 用：只取仍在推进的计划。
func (r *CollectionRepo) ListRunningPlans(ctx context.Context, limit int) ([]*CollectionPlan, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		select id, project_id, mode, status, current_stage, seed, deadline, created_at, updated_at
		  from collection_plans
		 where status = 'running'
		 order by updated_at asc
		 limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CollectionPlan
	for rows.Next() {
		var p CollectionPlan
		var deadline *time.Time
		if err := rows.Scan(&p.ID, &p.ProjectID, &p.Mode, &p.Status, &p.CurrentStage, &p.Seed,
			&deadline, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Deadline = deadline
		out = append(out, &p)
	}
	return out, rows.Err()
}

// StageTargets 取某阶段开始后落库的资产值，作为下一阶段的输入。
// raw_records 没有 task_id 列，用 project_id + observed_at 圈定阶段窗口；
// 值可能是域名/IP/URL，由下游模块自行判别与过滤。
func (r *CollectionRepo) StageTargets(ctx context.Context, projectID int64, since time.Time, limit int) ([]string, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	if limit <= 0 {
		limit = 1000
	}
	rows, err := r.pool.Query(ctx, `
		select distinct value
		  from raw_records
		 where project_id = $1
		   and observed_at >= $2
		   and value <> ''
		 order by value
		 limit $3`, projectID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
