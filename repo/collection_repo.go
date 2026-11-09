package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CollectionPlan 是信息收集阶段编排的父计划。
type CollectionPlan struct {
	ID           string     `json:"id"`
	ProjectID    int64      `json:"project_id"`
	Mode         string     `json:"mode"`
	Status       string     `json:"status"`
	CurrentStage string     `json:"current_stage"`
	Seed         string     `json:"-"`
	Deadline     *time.Time `json:"deadline,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// CollectionStage 是计划下的单个阶段账本。
type CollectionStage struct {
	ID         int64      `json:"id"`
	PlanID     string     `json:"plan_id"`
	Stage      string     `json:"stage"`
	TaskID     string     `json:"task_id,omitempty"`
	Status     string     `json:"status"`
	Attempt    int        `json:"attempt"`
	SkipReason string     `json:"skip_reason,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// CollectionStageView 是阶段账本 + 子任务摘要，避免前端为每个阶段再查一次任务。
type CollectionStageView struct {
	CollectionStage
	TaskName     string `json:"task_name,omitempty"`
	TaskStatus   string `json:"task_status,omitempty"`
	TaskProgress int    `json:"task_progress"`
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

// ListPlans 分页查询计划。过滤条件只允许 project_id / status（白名单），
// 排序固定 updated_at desc；page_size 上限 100，避免大结果集。
func (r *CollectionRepo) ListPlans(ctx context.Context, projectID int64, status string, page, pageSize int) ([]*CollectionPlan, int64, error) {
	if r == nil || r.pool == nil {
		return nil, 0, fmt.Errorf("数据层未初始化")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	const where = `where ($1 = 0 or project_id = $1) and ($2 = '' or status = $2)`

	var total int64
	if err := r.pool.QueryRow(ctx, `select count(*) from collection_plans `+where,
		projectID, status).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.pool.Query(ctx, `
		select id, project_id, mode, status, current_stage, seed, deadline, created_at, updated_at
		  from collection_plans `+where+`
		 order by updated_at desc
		 limit $3 offset $4`, projectID, status, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*CollectionPlan, 0, pageSize)
	for rows.Next() {
		var p CollectionPlan
		var deadline *time.Time
		if err := rows.Scan(&p.ID, &p.ProjectID, &p.Mode, &p.Status, &p.CurrentStage, &p.Seed,
			&deadline, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, 0, err
		}
		p.Deadline = deadline
		out = append(out, &p)
	}
	return out, total, rows.Err()
}

// RawSnapshotInput 是 raw_records 中可用于 AI 快照的字段子集。
type RawSnapshotInput struct {
	RawID    string
	Host     string
	Port     int
	Value    string
	Title    string
	Evidence string
}

// TaskRawForSnapshot 取某次任务落库的原始记录，供 raw_snapshots 写入。
// raw_records.task_id 来自 schema_governance.sql；没有 task_id 时返回空。
func (r *CollectionRepo) TaskRawForSnapshot(ctx context.Context, taskID string, limit int) ([]RawSnapshotInput, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
		select id::text, coalesce(host,''), coalesce(port,0),
		       coalesce(value,''), coalesce(title,''), coalesce(evidence::text,'{}')
		  from raw_records
		 where task_id = $1
		 order by id
		 limit $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]RawSnapshotInput, 0, 64)
	for rows.Next() {
		var v RawSnapshotInput
		if err := rows.Scan(&v.RawID, &v.Host, &v.Port, &v.Value, &v.Title, &v.Evidence); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListStagesWithTask 返回阶段账本 + 子任务摘要（left join tasks），
// 前端时间线一次查询即可，避免 N+1。
func (r *CollectionRepo) ListStagesWithTask(ctx context.Context, planID string) ([]*CollectionStageView, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	rows, err := r.pool.Query(ctx, `
		select cs.id, cs.plan_id, cs.stage, coalesce(cs.task_id,''), cs.status, cs.attempt,
		       cs.skip_reason, cs.started_at, cs.finished_at,
		       coalesce(t.name,''), coalesce(t.status,''), coalesce(t.progress,0)
		  from collection_stages cs
		  left join tasks t on t.id = cs.task_id
		 where cs.plan_id = $1
		 order by cs.id`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*CollectionStageView
	for rows.Next() {
		var v CollectionStageView
		var started, finished *time.Time
		if err := rows.Scan(&v.ID, &v.PlanID, &v.Stage, &v.TaskID, &v.Status, &v.Attempt,
			&v.SkipReason, &started, &finished,
			&v.TaskName, &v.TaskStatus, &v.TaskProgress); err != nil {
			return nil, err
		}
		v.StartedAt, v.FinishedAt = started, finished
		out = append(out, &v)
	}
	return out, rows.Err()
}
