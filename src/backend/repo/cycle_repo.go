package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// 治理域的「周期」三层：
//   seeds          采集种子（一个域名 / CIDR / 公司名）
//   monitoring_plans  种子上的计划（间隔 + 预算），到期就该起一次 run
//   runs           一次执行批次，cycle_start 是幂等键
//   run_targets    批次展开后的执行单元，靠租约 + SKIP LOCKED 领取
//
// 站点与证据的写入不在这里（见 assets_repo.go 的 ImportRecords）。

// Seed 是采集种子。
type Seed struct {
	ID         int64          `json:"id"`
	ProjectID  int64          `json:"project_id"`
	Kind       string         `json:"kind"`
	Value      string         `json:"value"`
	Capability map[string]any `json:"capability"`
	Enabled    bool           `json:"enabled"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Plan 是种子上的监控计划。ProjectID/SeedKind/SeedValue 由 join 带出，方便前端直接渲染。
type Plan struct {
	ID            int64          `json:"id"`
	SeedID        int64          `json:"seed_id"`
	SeedKind      string         `json:"seed_kind"`
	SeedValue     string         `json:"seed_value"`
	ProjectID     int64          `json:"project_id"`
	IntervalHours int            `json:"interval_hours"`
	Budget        map[string]any `json:"budget"`
	Enabled       bool           `json:"enabled"`
	NextRunAt     *time.Time     `json:"next_run_at"`
	LastRunAt     *time.Time     `json:"last_run_at"`
	CreatedAt     time.Time      `json:"created_at"`
}

// Run 是一次治理批次。
type Run struct {
	ID         int64          `json:"id"`
	PlanID     int64          `json:"plan_id"`
	ProjectID  int64          `json:"project_id"`
	CycleStart time.Time      `json:"cycle_start"`
	Status     string         `json:"status"`
	Budget     map[string]any `json:"budget"`
	StartedAt  *time.Time     `json:"started_at"`
	EndedAt    *time.Time     `json:"ended_at"`
	Stats      map[string]any `json:"stats"`
}

// RunTarget 是批次的执行单元。
type RunTarget struct {
	ID         int64      `json:"id"`
	RunID      int64      `json:"run_id"`
	ProjectID  int64      `json:"project_id"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	State      string     `json:"state"`
	Attempts   int        `json:"attempts"`
	LeaseUntil *time.Time `json:"lease_until"`
}

// SeedRepo 负责种子与计划。
type SeedRepo interface {
	ListSeeds(ctx context.Context, projectID int64) ([]*Seed, error)
	GetSeed(ctx context.Context, id int64) (*Seed, error)
	CreateSeed(ctx context.Context, s *Seed) error
	DeleteSeed(ctx context.Context, id int64) error

	ListPlans(ctx context.Context, projectID int64) ([]*Plan, error)
	GetPlan(ctx context.Context, id int64) (*Plan, error)
	CreatePlan(ctx context.Context, p *Plan) error
	UpdatePlan(ctx context.Context, id int64, enabled *bool, intervalHours *int) error
	DeletePlan(ctx context.Context, id int64) error
	// DuePlans 取到期待跑的计划。不加 FOR UPDATE：并发去重靠 runs 的 (plan_id, cycle_start) 唯一键。
	DuePlans(ctx context.Context, limit int) ([]*Plan, error)
	// MarkPlanRan 推进计划游标。next 由调用方按「上一周期 + 间隔」算，保持节奏不漂移。
	MarkPlanRan(ctx context.Context, id int64, next time.Time) error
}

// RunRepo 负责批次与目标。
type RunRepo interface {
	// CreateRun 幂等创建：同 (plan_id, cycle_start) 只会有一条。created=false 表示已存在。
	CreateRun(ctx context.Context, in CreateRunInput) (*Run, bool, error)
	GetRun(ctx context.Context, id int64) (*Run, error)
	ListRuns(ctx context.Context, projectID int64, limit int) ([]*Run, error)
	TouchRunStarted(ctx context.Context, id int64) error
	FinishRun(ctx context.Context, id int64, status string, stats map[string]any) error

	AddTargets(ctx context.Context, runID int64, targets []TargetInput) (int64, error)
	ListTargets(ctx context.Context, runID int64, state string, limit int) ([]*RunTarget, error)
	// ClaimTargets 领取执行单元：runID=0 表示跨批次领取（worker 用）。
	ClaimTargets(ctx context.Context, runID int64, lease time.Duration, limit int) ([]*RunTarget, error)
	CompleteTarget(ctx context.Context, id int64, state string) error
	// ReapTargets 回收租约过期的执行单元；重试超过 3 次的直接判 failed。
	ReapTargets(ctx context.Context) (int64, error)
	TargetStats(ctx context.Context, runID int64) (map[string]int, error)
}

// CreateRunInput 是建批次的入参。
type CreateRunInput struct {
	PlanID     int64
	ProjectID  int64
	CycleStart time.Time
	Budget     map[string]any
}

// TargetInput 是展开出来的一条执行单元。
type TargetInput struct {
	Host string
	Port int
}

type seedRepo struct{ r *Repo }

func (r *Repo) Seeds() SeedRepo { return &seedRepo{r: r} }

const seedColumns = `id, project_id, kind, value, capability, enabled, created_at`

func scanSeed(row pgx.Row) (*Seed, error) {
	var (
		s   Seed
		cap []byte
	)
	if err := row.Scan(&s.ID, &s.ProjectID, &s.Kind, &s.Value, &cap, &s.Enabled, &s.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.CreatedAt = s.CreatedAt.UTC()
	if len(cap) > 0 {
		_ = json.Unmarshal(cap, &s.Capability)
	}
	if s.Capability == nil {
		s.Capability = map[string]any{}
	}
	return &s, nil
}

func (r *seedRepo) ListSeeds(ctx context.Context, projectID int64) ([]*Seed, error) {
	q := `select ` + seedColumns + ` from seeds`
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` where project_id = $1`
	}
	q += ` order by id desc`

	rows, err := r.r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Seed{}
	for rows.Next() {
		s, err := scanSeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *seedRepo) GetSeed(ctx context.Context, id int64) (*Seed, error) {
	return scanSeed(r.r.pool.QueryRow(ctx, `select `+seedColumns+` from seeds where id = $1`, id))
}

func (r *seedRepo) CreateSeed(ctx context.Context, s *Seed) error {
	capability, err := jsonb(s.Capability)
	if err != nil {
		return fmt.Errorf("序列化 capability 失败: %w", err)
	}
	err = r.r.pool.QueryRow(ctx,
		`insert into seeds (project_id, kind, value, capability, enabled)
		 values ($1,$2,$3,$4,$5) returning id, created_at`,
		s.ProjectID, s.Kind, s.Value, capability, s.Enabled).Scan(&s.ID, &s.CreatedAt)
	if isUniqueViolation(err) {
		return fmt.Errorf("同一个项目下已存在相同种子（kind=%s value=%s）", s.Kind, s.Value)
	}
	if err != nil {
		return err
	}
	s.CreatedAt = s.CreatedAt.UTC()
	return nil
}

func (r *seedRepo) DeleteSeed(ctx context.Context, id int64) error {
	tag, err := r.r.pool.Exec(ctx, `delete from seeds where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const planColumns = `p.id, p.seed_id, s.kind, s.value, s.project_id, p.interval_hours, p.budget,
	p.enabled, p.next_run_at, p.last_run_at, p.created_at`

const planFrom = ` from monitoring_plans p join seeds s on s.id = p.seed_id`

func scanPlan(row pgx.Row) (*Plan, error) {
	var (
		p      Plan
		budget []byte
	)
	if err := row.Scan(&p.ID, &p.SeedID, &p.SeedKind, &p.SeedValue, &p.ProjectID,
		&p.IntervalHours, &budget, &p.Enabled, &p.NextRunAt, &p.LastRunAt, &p.CreatedAt); err != nil {
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

func (r *seedRepo) ListPlans(ctx context.Context, projectID int64) ([]*Plan, error) {
	q := `select ` + planColumns + planFrom
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` where s.project_id = $1`
	}
	q += ` order by p.id desc`

	rows, err := r.r.pool.Query(ctx, q, args...)
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

func (r *seedRepo) GetPlan(ctx context.Context, id int64) (*Plan, error) {
	return scanPlan(r.r.pool.QueryRow(ctx, `select `+planColumns+planFrom+` where p.id = $1`, id))
}

func (r *seedRepo) CreatePlan(ctx context.Context, p *Plan) error {
	budget, err := jsonb(p.Budget)
	if err != nil {
		return fmt.Errorf("序列化 budget 失败: %w", err)
	}
	// 新计划立刻到期：第一次 tick 就会起一个 run，不用等到下一个间隔
	err = r.r.pool.QueryRow(ctx,
		`insert into monitoring_plans (seed_id, interval_hours, budget, enabled, next_run_at)
		 values ($1,$2,$3,$4, now()) returning id, created_at`,
		p.SeedID, p.IntervalHours, budget, p.Enabled).Scan(&p.ID, &p.CreatedAt)
	if err != nil {
		return err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return nil
}

func (r *seedRepo) UpdatePlan(ctx context.Context, id int64, enabled *bool, intervalHours *int) error {
	tag, err := r.r.pool.Exec(ctx,
		`update monitoring_plans
		    set enabled = coalesce($2, enabled),
		        interval_hours = coalesce($3, interval_hours)
		  where id = $1`, id, enabled, intervalHours)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *seedRepo) DeletePlan(ctx context.Context, id int64) error {
	tag, err := r.r.pool.Exec(ctx, `delete from monitoring_plans where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *seedRepo) DuePlans(ctx context.Context, limit int) ([]*Plan, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := r.r.pool.Query(ctx,
		`select `+planColumns+planFrom+`
		  where p.enabled and s.enabled
		    and (p.next_run_at is null or p.next_run_at <= now())
		  order by coalesce(p.next_run_at, to_timestamp(0)), p.id
		  limit $1`, limit)
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

func (r *seedRepo) MarkPlanRan(ctx context.Context, id int64, next time.Time) error {
	_, err := r.r.pool.Exec(ctx,
		`update monitoring_plans set last_run_at = now(), next_run_at = $2 where id = $1`,
		id, next.UTC())
	return err
}

// --- 批次 ---

type runRepo struct{ r *Repo }

func (r *Repo) Runs() RunRepo { return &runRepo{r: r} }

const runColumns = `id, plan_id, project_id, cycle_start, status, budget, started_at, ended_at, stats`

func scanRun(row pgx.Row) (*Run, error) {
	var (
		run    Run
		budget []byte
		stats  []byte
	)
	if err := row.Scan(&run.ID, &run.PlanID, &run.ProjectID, &run.CycleStart, &run.Status,
		&budget, &run.StartedAt, &run.EndedAt, &stats); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	run.CycleStart = run.CycleStart.UTC()
	if len(budget) > 0 {
		_ = json.Unmarshal(budget, &run.Budget)
	}
	if len(stats) > 0 {
		_ = json.Unmarshal(stats, &run.Stats)
	}
	if run.Budget == nil {
		run.Budget = map[string]any{}
	}
	if run.Stats == nil {
		run.Stats = map[string]any{}
	}
	return &run, nil
}

func (r *runRepo) CreateRun(ctx context.Context, in CreateRunInput) (*Run, bool, error) {
	budget, err := jsonb(in.Budget)
	if err != nil {
		return nil, false, fmt.Errorf("序列化 budget 失败: %w", err)
	}
	run, err := scanRun(r.r.pool.QueryRow(ctx,
		`insert into runs (plan_id, project_id, cycle_start, budget)
		 values ($1,$2,$3,$4)
		 on conflict (plan_id, cycle_start) do nothing
		 returning `+runColumns,
		in.PlanID, in.ProjectID, in.CycleStart.UTC(), budget))
	if err == nil {
		return run, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	// 已存在：取回来，交给调用方决定是否补展开
	run, err = scanRun(r.r.pool.QueryRow(ctx,
		`select `+runColumns+` from runs where plan_id = $1 and cycle_start = $2`,
		in.PlanID, in.CycleStart.UTC()))
	if err != nil {
		return nil, false, err
	}
	return run, false, nil
}

func (r *runRepo) GetRun(ctx context.Context, id int64) (*Run, error) {
	return scanRun(r.r.pool.QueryRow(ctx, `select `+runColumns+` from runs where id = $1`, id))
}

func (r *runRepo) ListRuns(ctx context.Context, projectID int64, limit int) ([]*Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `select ` + runColumns + ` from runs`
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` where project_id = $1`
	}
	args = append(args, limit)
	q += fmt.Sprintf(` order by cycle_start desc, id desc limit $%d`, len(args))

	rows, err := r.r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Run{}
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (r *runRepo) TouchRunStarted(ctx context.Context, id int64) error {
	_, err := r.r.pool.Exec(ctx,
		`update runs set status = case when status = 'queued' then 'running' else status end,
		        started_at = coalesce(started_at, now())
		  where id = $1`, id)
	return err
}

func (r *runRepo) FinishRun(ctx context.Context, id int64, status string, stats map[string]any) error {
	s, err := jsonb(stats)
	if err != nil {
		return fmt.Errorf("序列化 stats 失败: %w", err)
	}
	_, err = r.r.pool.Exec(ctx,
		`update runs set status = $2, stats = $3, ended_at = now(),
		        started_at = coalesce(started_at, now())
		  where id = $1`, id, status, s)
	return err
}

func (r *runRepo) AddTargets(ctx context.Context, runID int64, targets []TargetInput) (int64, error) {
	if len(targets) == 0 {
		return 0, nil
	}
	hosts := make([]string, 0, len(targets))
	ports := make([]int32, 0, len(targets))
	for _, t := range targets {
		hosts = append(hosts, t.Host)
		ports = append(ports, int32(t.Port))
	}
	// 批量展开：一条 SQL 落完，靠 (run_id, host, port) 唯一键去重
	tag, err := r.r.pool.Exec(ctx,
		`insert into run_targets (run_id, host, port)
		 select $1, t.host, t.port from unnest($2::text[], $3::int[]) as t(host, port)
		 on conflict (run_id, host, port) do nothing`, runID, hosts, ports)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *runRepo) ListTargets(ctx context.Context, runID int64, state string, limit int) ([]*RunTarget, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.r.pool.Query(ctx,
		`select t.id, t.run_id, (select project_id from runs r where r.id = t.run_id),
		        t.host, t.port, t.state, t.attempts, t.lease_until
		   from run_targets t
		  where t.run_id = $1 and ($2 = '' or t.state = $2)
		  order by t.id limit $3`, runID, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*RunTarget{}
	for rows.Next() {
		var t RunTarget
		if err := rows.Scan(&t.ID, &t.RunID, &t.ProjectID, &t.Host, &t.Port,
			&t.State, &t.Attempts, &t.LeaseUntil); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (r *runRepo) ClaimTargets(ctx context.Context, runID int64, lease time.Duration, limit int) ([]*RunTarget, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if lease <= 0 {
		lease = 5 * time.Minute
	}
	rows, err := r.r.pool.Query(ctx,
		`with picked as (
		    select id from run_targets
		     where ($1 = 0 or run_id = $1)
		       and (state = 'pending' or (state = 'running' and lease_until < now()))
		     order by id
		     for update skip locked
		     limit $2)
		 update run_targets t
		    set state = 'running',
		        lease_until = now() + make_interval(secs => $3),
		        attempts = t.attempts + 1
		   from picked
		  where t.id = picked.id
		  returning t.id, t.run_id, (select project_id from runs r where r.id = t.run_id),
		            t.host, t.port, t.state, t.attempts, t.lease_until`,
		runID, limit, lease.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*RunTarget{}
	for rows.Next() {
		var t RunTarget
		if err := rows.Scan(&t.ID, &t.RunID, &t.ProjectID, &t.Host, &t.Port,
			&t.State, &t.Attempts, &t.LeaseUntil); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (r *runRepo) CompleteTarget(ctx context.Context, id int64, state string) error {
	_, err := r.r.pool.Exec(ctx,
		`update run_targets set state = $2, lease_until = null where id = $1`, id, state)
	return err
}

func (r *runRepo) ReapTargets(ctx context.Context) (int64, error) {
	// 与 task_jobs 的 reaper 同一套语义：过期回收，超过重试次数判死
	tag, err := r.r.pool.Exec(ctx,
		`update run_targets
		    set state = case when attempts >= 3 then 'failed' else 'pending' end,
		        lease_until = null
		  where state = 'running' and lease_until < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *runRepo) TargetStats(ctx context.Context, runID int64) (map[string]int, error) {
	rows, err := r.r.pool.Query(ctx,
		`select state, count(*) from run_targets where run_id = $1 group by state`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var (
			state string
			n     int
		)
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		out[state] = n
	}
	return out, rows.Err()
}
