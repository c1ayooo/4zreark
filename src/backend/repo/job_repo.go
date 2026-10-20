package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// task_jobs.status 取值。queued/running 是过程态，done/failed/dead 是终态。
const (
	JobQueued  = "queued"
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
	JobDead    = "dead"
)

// task_jobs.kind 区分两类作业：两者共用一张表，但消费方和语义完全不同。
//
//	scan：扫描任务作业，由 TaskExecutor 消费，task_id 指向 tasks 表记录；
//	job ：通用队列作业（/api/queue 那套接口），由 service/queue 消费，不关联 tasks。
const (
	JobKindScan = "scan"
	JobKindJob  = "job"
)

// Job 对应 task_jobs 一行。
type Job struct {
	ID             int64
	TaskID         string
	Kind           string
	Stage          string
	Priority       int
	Status         string
	Payload        []byte
	Checkpoint     []byte
	Attempts       int
	MaxAttempts    int
	WorkerID       string
	ScheduledAt    time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LeaseExpiresAt *time.Time
}

// EnqueueJobInput 是入队参数。ScheduledAt 为零值时表示立即到期。
type EnqueueJobInput struct {
	TaskID      string
	Kind        string
	Stage       string
	Priority    int
	Payload     any
	MaxAttempts int
	ScheduledAt time.Time
}

// JobRepo 是 task_jobs 的唯一数据入口。
type JobRepo interface {
	Enqueue(ctx context.Context, in EnqueueJobInput) (int64, error)
	// ClaimScan 领取一条属于「可执行扫描任务」的作业：只要 tasks 状态是 pending/running。
	ClaimScan(ctx context.Context, workerID string, lease time.Duration) (*Job, error)
	// ClaimGeneric 领取一条通用队列作业。
	ClaimGeneric(ctx context.Context, workerID string, lease time.Duration) (*Job, error)
	Renew(ctx context.Context, id int64, lease time.Duration) error
	Complete(ctx context.Context, id int64, checkpoint any) error
	// Retry 失败重试：未超次数回到 queued，超了标 dead。返回落定的状态。
	Retry(ctx context.Context, id int64, errMsg string, backoff time.Duration) (string, error)
	GetByID(ctx context.Context, id int64) (*Job, error)
	List(ctx context.Context, kind, status string, limit int) ([]*Job, error)
	Stats(ctx context.Context, kind string) (map[string]int, error)
	// CountScheduled 统计还没到期的排队作业数（延迟执行的那部分）。
	CountScheduled(ctx context.Context, kind string) (int, error)
	RetryDead(ctx context.Context, id int64) error
	ClearDead(ctx context.Context, kind string) error
	// DiscardQueuedForTask 丢弃某任务还没被领取的作业（暂停/取消时用），返回条数。
	DiscardQueuedForTask(ctx context.Context, taskID string) (int, error)
	// Reap 回收租约过期的 running 作业，顺带清理过期的黑名单与去重键。
	Reap(ctx context.Context, limit int) (int, error)
	ActiveWorkers(ctx context.Context, kind string) ([]map[string]any, error)
}

type jobRepo struct{ r *Repo }

const jobColumns = `id, task_id, kind, stage, priority, status, payload, checkpoint,
	attempts, max_attempts, coalesce(worker_id, ''), scheduled_at, created_at, updated_at, lease_expires_at`

func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.TaskID, &j.Kind, &j.Stage, &j.Priority, &j.Status,
		&j.Payload, &j.Checkpoint, &j.Attempts, &j.MaxAttempts, &j.WorkerID,
		&j.ScheduledAt, &j.CreatedAt, &j.UpdatedAt, &j.LeaseExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (r *jobRepo) Enqueue(ctx context.Context, in EnqueueJobInput) (int64, error) {
	if in.Kind == "" {
		in.Kind = JobKindScan
	}
	if in.MaxAttempts <= 0 {
		in.MaxAttempts = 3
	}
	payload, err := jsonb(in.Payload)
	if err != nil {
		return 0, fmt.Errorf("序列化作业载荷失败: %w", err)
	}

	var id int64
	err = r.r.pool.QueryRow(ctx,
		`insert into task_jobs (task_id, kind, stage, priority, payload, max_attempts, scheduled_at)
		 values ($1,$2,$3,$4,$5,$6, coalesce($7::timestamptz, now()))
		 returning id`,
		in.TaskID, in.Kind, in.Stage, in.Priority, payload, in.MaxAttempts, timeToPG(in.ScheduledAt),
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// claim 是领取的公共实现：子查询里 FOR UPDATE SKIP LOCKED 选一行，外层 UPDATE 打上租约。
// joinCond 由调用方给定（扫描作业需要联 tasks 表过滤任务状态）。
func (r *jobRepo) claim(ctx context.Context, kind, workerID string, lease time.Duration, joinCond string) (*Job, error) {
	stmt := `update task_jobs j
	            set status = 'running',
	                worker_id = $1,
	                attempts = j.attempts + 1,
	                lease_expires_at = now() + make_interval(secs => $2),
	                updated_at = now()
	          where j.id = (
	                select j2.id
	                  from task_jobs j2 ` + joinCond + `
	                 where j2.kind = $3
	                   and j2.status = 'queued'
	                   and j2.scheduled_at <= now()
	                 order by j2.priority desc, j2.id
	                 for update of j2 skip locked
	                 limit 1)
	      returning ` + jobColumns

	job, err := scanJob(r.r.pool.QueryRow(ctx, stmt, workerID, lease.Seconds(), kind))
	if errors.Is(err, ErrNotFound) {
		// 队列空，不是错误
		return nil, nil
	}
	return job, err
}

func (r *jobRepo) ClaimScan(ctx context.Context, workerID string, lease time.Duration) (*Job, error) {
	return r.claim(ctx, JobKindScan, workerID, lease,
		`join tasks t on t.id = j2.task_id and t.status in ('pending','running')`)
}

func (r *jobRepo) ClaimGeneric(ctx context.Context, workerID string, lease time.Duration) (*Job, error) {
	return r.claim(ctx, JobKindJob, workerID, lease, ``)
}

func (r *jobRepo) Renew(ctx context.Context, id int64, lease time.Duration) error {
	_, err := r.r.pool.Exec(ctx,
		`update task_jobs
		    set lease_expires_at = now() + make_interval(secs => $2), updated_at = now()
		  where id = $1 and status = 'running'`,
		id, lease.Seconds())
	return err
}

func (r *jobRepo) Complete(ctx context.Context, id int64, checkpoint any) error {
	stmt := `update task_jobs
	            set status = 'done', lease_expires_at = null, worker_id = null, updated_at = now()
	          where id = $1`
	args := []any{id}
	if checkpoint != nil {
		b, err := jsonb(checkpoint)
		if err != nil {
			return fmt.Errorf("序列化作业结果失败: %w", err)
		}
		stmt = `update task_jobs
		           set status = 'done', lease_expires_at = null, worker_id = null,
		               checkpoint = checkpoint || $2::jsonb, updated_at = now()
		         where id = $1`
		args = append(args, b)
	}
	tag, err := r.r.pool.Exec(ctx, stmt, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *jobRepo) Retry(ctx context.Context, id int64, errMsg string, backoff time.Duration) (string, error) {
	var status string
	err := r.r.pool.QueryRow(ctx,
		`update task_jobs
		    set status = case when attempts >= max_attempts then 'dead' else 'queued' end,
		        worker_id = null,
		        lease_expires_at = null,
		        scheduled_at = now() + make_interval(secs => $2),
		        checkpoint = checkpoint || jsonb_build_object('last_error', $3::text),
		        updated_at = now()
		  where id = $1
		 returning status`,
		id, backoff.Seconds(), errMsg).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return status, err
}

func (r *jobRepo) GetByID(ctx context.Context, id int64) (*Job, error) {
	return scanJob(r.r.pool.QueryRow(ctx,
		`select `+jobColumns+` from task_jobs where id = $1`, id))
}

func (r *jobRepo) List(ctx context.Context, kind, status string, limit int) ([]*Job, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := r.r.pool.Query(ctx,
		`select `+jobColumns+`
		   from task_jobs
		  where ($1 = '' or kind = $1)
		    and ($2 = '' or status = $2)
		  order by priority desc, id
		  limit $3`, kind, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (r *jobRepo) Stats(ctx context.Context, kind string) (map[string]int, error) {
	rows, err := r.r.pool.Query(ctx,
		`select status, count(*) from task_jobs where ($1 = '' or kind = $1) group by status`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var (
			s string
			n int
		)
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

func (r *jobRepo) CountScheduled(ctx context.Context, kind string) (int, error) {
	var n int
	err := r.r.pool.QueryRow(ctx,
		`select count(*) from task_jobs
		  where status = 'queued' and scheduled_at > now() and ($1 = '' or kind = $1)`, kind).Scan(&n)
	return n, err
}

func (r *jobRepo) RetryDead(ctx context.Context, id int64) error {
	tag, err := r.r.pool.Exec(ctx,
		`update task_jobs
		    set status = 'queued', attempts = 0, worker_id = null, lease_expires_at = null,
		        scheduled_at = now(),
		        checkpoint = checkpoint - 'last_error',
		        updated_at = now()
		  where id = $1 and status = 'dead'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *jobRepo) ClearDead(ctx context.Context, kind string) error {
	_, err := r.r.pool.Exec(ctx,
		`delete from task_jobs where status = 'dead' and ($1 = '' or kind = $1)`, kind)
	return err
}

func (r *jobRepo) DiscardQueuedForTask(ctx context.Context, taskID string) (int, error) {
	if _, err := idFromString(taskID); err != nil {
		return 0, ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx,
		`update task_jobs
		    set status = 'done', updated_at = now(),
		        checkpoint = checkpoint || jsonb_build_object('last_error', '任务已暂停或取消，排队作业被丢弃')
		  where task_id = $1 and status = 'queued'`, taskID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (r *jobRepo) Reap(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = 50
	}
	var reaped int
	err := r.r.pool.QueryRow(ctx,
		`with expired as (
		     select id from task_jobs
		      where status = 'running' and lease_expires_at < now()
		      order by lease_expires_at
		      limit $1
		 ), upd as (
		     update task_jobs j
		        set status = case when j.attempts >= j.max_attempts then 'dead' else 'queued' end,
		            worker_id = null,
		            lease_expires_at = null,
		            scheduled_at = now(),
		            checkpoint = checkpoint || jsonb_build_object('last_error', '租约过期，作业被回收'),
		            updated_at = now()
		      where j.id in (select id from expired)
		      returning j.id
		 )
		 select count(*) from upd`, limit).Scan(&reaped)
	if err != nil {
		return 0, err
	}

	// 顺带清理两张会无限增长的表：过期黑名单、7 天前的去重键。
	// 清理失败不影响回收结果，下次 reaper 还会再来一次，所以这里只做尽力而为。
	_, _ = r.r.pool.Exec(ctx, `delete from token_blacklist where expires_at < now()`)
	_, _ = r.r.pool.Exec(ctx, `delete from result_dedup where created_at < now() - interval '7 days'`)

	return reaped, nil
}

func (r *jobRepo) ActiveWorkers(ctx context.Context, kind string) ([]map[string]any, error) {
	rows, err := r.r.pool.Query(ctx,
		`select worker_id, count(*) as jobs,
		        min(updated_at) as since,
		        min(lease_expires_at) as lease_until
		   from task_jobs
		  where status = 'running' and worker_id is not null and ($1 = '' or kind = $1)
		  group by worker_id
		  order by worker_id`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var (
			workerID string
			jobs     int
			since    time.Time
			until    *time.Time
		)
		if err := rows.Scan(&workerID, &jobs, &since, &until); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"worker_id":   workerID,
			"jobs":        jobs,
			"since":       since,
			"lease_until": timeFromPG(until),
		})
	}
	return out, rows.Err()
}
