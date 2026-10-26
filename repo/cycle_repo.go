package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 巡航触发方式。
const (
	// PlanTriggerInterval 固定周期（默认，原行为）。
	PlanTriggerInterval = "interval"
	// PlanTriggerOnChange 只在项目出现资产变更时跑。
	PlanTriggerOnChange = "on_change"
	// PlanTriggerBoth 到点跑，有变更也提前跑。
	PlanTriggerBoth = "both"
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
	// TriggerMode 决定这个计划什么时候跑：
	//   interval  固定周期（默认，原行为）
	//   on_change 只在项目出现资产变更时跑
	//   both      到点跑，有变更也提前跑
	TriggerMode           string     `json:"trigger_mode"`
	ChangeCooldownMinutes int        `json:"change_cooldown_minutes"`
	Enabled               bool       `json:"enabled"`
	NextRunAt             *time.Time `json:"next_run_at"`
	LastRunAt             *time.Time `json:"last_run_at"`
	CreatedAt             time.Time  `json:"created_at"`
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
	ID         int64          `json:"id"`
	RunID      int64          `json:"run_id"`
	ProjectID  int64          `json:"project_id"`
	Host       string         `json:"host"`
	Port       int            `json:"port"`
	Capability map[string]any `json:"capability"`
	State      string         `json:"state"`
	Attempts   int            `json:"attempts"`
	LeaseUntil *time.Time     `json:"lease_until"`
}

// SeedRepo 负责种子与计划。
type SeedRepo interface {
	ListSeeds(ctx context.Context, projectID int64) ([]*Seed, error)
	GetSeed(ctx context.Context, id int64) (*Seed, error)
	CreateSeed(ctx context.Context, s *Seed) error
	DeleteSeed(ctx context.Context, id int64) error

	UpdatePlan(ctx context.Context, id int64, enabled *bool, intervalHours *int, triggerMode *string, cooldownMinutes *int) error
	ListPlans(ctx context.Context, projectID int64) ([]*Plan, error)
	GetPlan(ctx context.Context, id int64) (*Plan, error)
	CreatePlan(ctx context.Context, p *Plan) error
	DeletePlan(ctx context.Context, id int64) error
	// DuePlans 取到期待跑的计划。不加 FOR UPDATE：并发去重靠 runs 的 (plan_id, cycle_start) 唯一键。
	DuePlans(ctx context.Context, limit int) ([]*Plan, error)
	// ChangeTriggeredPlans 取「资产有变更且过了冷却期」的计划（on_change / both）。
	ChangeTriggeredPlans(ctx context.Context, limit int) ([]*Plan, error)
	// MarkPlanRan 推进计划游标。next 由调用方按「上一周期 + 间隔」算，保持节奏不漂移。
	MarkPlanRan(ctx context.Context, id int64, next time.Time) error
	// MarkPlanChangeRan 只更新 last_run_at，不动周期游标（变更触发不改变原定节奏）。
	MarkPlanChangeRan(ctx context.Context, id int64) error
}

// RunRepo 负责批次与目标。
type RunRepo interface {
	// CreateRun 幂等创建：同 (plan_id, cycle_start) 只会有一条。created=false 表示已存在。
	CreateRun(ctx context.Context, in CreateRunInput) (*Run, bool, error)
	GetRun(ctx context.Context, id int64) (*Run, error)
	ListRuns(ctx context.Context, projectID int64, limit int) ([]*Run, error)
	TouchRunStarted(ctx context.Context, id int64) error
	FinishRun(ctx context.Context, id int64, status string, stats map[string]any) error
	// MergeRunStats 合并写入统计字段，不覆盖已有的 empty_reason 等键。
	MergeRunStats(ctx context.Context, id int64, stats map[string]any) error

	AddTargets(ctx context.Context, runID int64, targets []TargetInput) (int64, error)
	ListTargets(ctx context.Context, runID int64, state string, limit int) ([]*RunTarget, error)
	// ClaimTargets 领取执行单元：runID=0 表示跨批次领取（worker 用）。
	ClaimTargets(ctx context.Context, runID int64, lease time.Duration, limit int) ([]*RunTarget, error)
	CompleteTarget(ctx context.Context, id int64, state string) error
	// ReapTargets 回收租约过期的执行单元；重试超过 3 次的直接判 failed。
	ReapTargets(ctx context.Context) (int64, error)
	TargetStats(ctx context.Context, runID int64) (map[string]int, error)

	// G4：每日预算切片
	// TargetsAddedToday 统计某项目今天（DB 时区）新增的执行单元数。
	TargetsAddedToday(ctx context.Context, projectID int64) (int64, error)
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
	Host       string         `json:"host"`
	Port       int            `json:"port"`
	Capability map[string]any `json:"capability,omitempty"`
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
		return fmt.Errorf("%w: 同一个项目下已存在相同种子（kind=%s value=%s）", ErrDuplicate, s.Kind, s.Value)
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
	p.trigger_mode, p.change_cooldown_minutes, p.enabled, p.next_run_at, p.last_run_at, p.created_at`

const planFrom = ` from monitoring_plans p join seeds s on s.id = p.seed_id join projects pr on pr.id = s.project_id`

func scanPlan(row pgx.Row) (*Plan, error) {
	var (
		p      Plan
		budget []byte
	)
	if err := row.Scan(&p.ID, &p.SeedID, &p.SeedKind, &p.SeedValue, &p.ProjectID,
		&p.IntervalHours, &budget, &p.TriggerMode, &p.ChangeCooldownMinutes,
		&p.Enabled, &p.NextRunAt, &p.LastRunAt, &p.CreatedAt); err != nil {
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
	if strings.TrimSpace(p.TriggerMode) == "" {
		p.TriggerMode = PlanTriggerInterval
	}
	if p.ChangeCooldownMinutes <= 0 {
		p.ChangeCooldownMinutes = 10
	}
	// 新计划立刻到期：第一次 tick 就会起一个 run，不用等到下一个间隔
	err = r.r.pool.QueryRow(ctx,
		`insert into monitoring_plans (seed_id, interval_hours, budget, trigger_mode, change_cooldown_minutes, enabled, next_run_at)
		 values ($1,$2,$3,$4,$5,$6, now()) returning id, created_at`,
		p.SeedID, p.IntervalHours, budget, p.TriggerMode, p.ChangeCooldownMinutes,
		p.Enabled).Scan(&p.ID, &p.CreatedAt)
	if err != nil {
		return err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return nil
}

func (r *seedRepo) UpdatePlan(ctx context.Context, id int64, enabled *bool, intervalHours *int, triggerMode *string, cooldown *int) error {
	if triggerMode != nil {
		m := strings.ToLower(strings.TrimSpace(*triggerMode))
		switch m {
		case PlanTriggerInterval, PlanTriggerOnChange, PlanTriggerBoth:
			*triggerMode = m
		default:
			return fmt.Errorf("trigger_mode 只支持 interval / on_change / both")
		}
	}
	if cooldown != nil && (*cooldown < 1 || *cooldown > 1440) {
		return fmt.Errorf("change_cooldown_minutes 需在 1..1440")
	}
	tag, err := r.r.pool.Exec(ctx,
		`update monitoring_plans
		    set enabled = coalesce($2, enabled),
		        interval_hours = coalesce($3, interval_hours),
		        trigger_mode = coalesce($4, trigger_mode),
		        change_cooldown_minutes = coalesce($5, change_cooldown_minutes)
		  where id = $1`, id, enabled, intervalHours, triggerMode, cooldown)
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
		  where p.enabled and s.enabled and not pr.collection_paused
		    and p.trigger_mode in ('interval', 'both')
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
		`update runs set status = $2, stats = stats || $3::jsonb, ended_at = now(),
		        started_at = coalesce(started_at, now())
		  where id = $1`, id, status, s)
	return err
}

func (r *runRepo) MergeRunStats(ctx context.Context, id int64, stats map[string]any) error {
	s, err := jsonb(stats)
	if err != nil {
		return fmt.Errorf("序列化 stats 失败: %w", err)
	}
	_, err = r.r.pool.Exec(ctx, `update runs set stats = stats || $2::jsonb where id = $1`, id, s)
	return err
}

func (r *runRepo) AddTargets(ctx context.Context, runID int64, targets []TargetInput) (int64, error) {
	if len(targets) == 0 {
		return 0, nil
	}
	hosts := make([]string, 0, len(targets))
	ports := make([]int32, 0, len(targets))
	caps := make([]string, 0, len(targets))
	for _, t := range targets {
		hosts = append(hosts, t.Host)
		ports = append(ports, int32(t.Port))
		capability := t.Capability
		if capability == nil {
			capability = map[string]any{"probe": true}
		}
		b, err := json.Marshal(capability)
		if err != nil {
			return 0, fmt.Errorf("序列化目标 capability 失败: %w", err)
		}
		caps = append(caps, string(b))
	}
	// 批量展开：一条 SQL 落完，靠 (run_id, host, port) 唯一键去重
	tag, err := r.r.pool.Exec(ctx,
		`insert into run_targets (run_id, host, port, capability)
		 select $1, t.host, t.port, t.capability::jsonb
		   from unnest($2::text[], $3::int[], $4::text[]) as t(host, port, capability)
		 on conflict (run_id, host, port) do nothing`, runID, hosts, ports, caps)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func scanRunTarget(scan func(...any) error) (*RunTarget, error) {
	var (
		t    RunTarget
		capB []byte
	)
	if err := scan(&t.ID, &t.RunID, &t.ProjectID, &t.Host, &t.Port, &capB,
		&t.State, &t.Attempts, &t.LeaseUntil); err != nil {
		return nil, err
	}
	if len(capB) > 0 {
		_ = json.Unmarshal(capB, &t.Capability)
	}
	if t.Capability == nil {
		t.Capability = map[string]any{}
	}
	return &t, nil
}

func (r *runRepo) ListTargets(ctx context.Context, runID int64, state string, limit int) ([]*RunTarget, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.r.pool.Query(ctx,
		`select t.id, t.run_id, (select project_id from runs r where r.id = t.run_id),
		        t.host, t.port, t.capability, t.state, t.attempts, t.lease_until
		   from run_targets t
		  where t.run_id = $1 and ($2 = '' or t.state = $2)
		  order by t.id limit $3`, runID, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*RunTarget{}
	for rows.Next() {
		t, err := scanRunTarget(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
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
		            t.host, t.port, t.capability, t.state, t.attempts, t.lease_until`,
		runID, limit, lease.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*RunTarget{}
	for rows.Next() {
		t, err := scanRunTarget(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
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

// TargetsAddedToday 统计项目在今天新增的执行单元（所有计划共享一个每日预算）。
func (r *runRepo) TargetsAddedToday(ctx context.Context, projectID int64) (int64, error) {
	var n int64
	err := r.r.pool.QueryRow(ctx, `
select count(*)
  from run_targets t
  join runs r on r.id = t.run_id
 where r.project_id = $1
   and r.cycle_start >= date_trunc('day', now())`, projectID).Scan(&n)
	return n, err
}

// ChangeTriggeredPlans 取「项目有资产变更、且已过冷却期」的计划。
// 变更信号来自 asset_events（first_seen / reappear / takeover 都算），
// 但探测类 attribute_change 噪声大，只认新增与重现两类。
// 冷却期用 last_run_at + change_cooldown_minutes 计算，防止一次采集风暴
// 触发一串批次。
func (r *seedRepo) ChangeTriggeredPlans(ctx context.Context, limit int) ([]*Plan, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := r.r.pool.Query(ctx,
		`select `+planColumns+planFrom+`
		  where p.enabled and s.enabled and not pr.collection_paused
		    and p.trigger_mode in ('on_change', 'both')
		    and exists (
		        select 1 from asset_events ev
		          where ev.project_id = s.project_id
		            and ev.event_type in ('first_seen', 'reappear', 'takeover')
		            and ev.created_at > coalesce(p.last_run_at, to_timestamp(0))
		            and ev.created_at <= now() - make_interval(mins => p.change_cooldown_minutes::int)
		    )
		  order by coalesce(p.last_run_at, to_timestamp(0)), p.id
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

// MarkPlanChangeRan 只推进 last_run_at：变更触发是额外跑一次，
// 不该把 next_run_at 也一起提前，否则固定周期的节奏会被打乱。
func (r *seedRepo) MarkPlanChangeRan(ctx context.Context, id int64) error {
	_, err := r.r.pool.Exec(ctx,
		`update monitoring_plans set last_run_at = now() where id = $1`, id)
	return err
}
