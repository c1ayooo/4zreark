package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/c1ayooo/4zreark/oid"
)

// 种子收集队列：icp_queries 同款范式——单 worker 串行、DB 状态机
// queued→running→done/error、claim 走条件更新防双跑。

type SeedCollectionJob struct {
	ID         string     `json:"id"`
	ProjectID  int64      `json:"project_id"`
	SeedID     int64      `json:"seed_id"`
	Kind       string     `json:"kind"`
	Value      string     `json:"value"`
	Status     string     `json:"status"`
	Found      int        `json:"found"`
	Error      string     `json:"error"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

type SeedCollectionRepo interface {
	CreateJob(ctx context.Context, projectID, seedID int64, kind, value string) (*SeedCollectionJob, error)
	ClaimJob(ctx context.Context, id string) (*SeedCollectionJob, error)
	ResetStaleRunning(ctx context.Context) (int64, error)
	ListQueuedJobIDs(ctx context.Context, limit int) ([]string, error)
	FinishJob(ctx context.Context, id string, status string, found int, errMsg string) error
	ListJobs(ctx context.Context, projectID int64, limit int) ([]SeedCollectionJob, error)
	CountActive(ctx context.Context, projectID int64) (int64, error)
	ListActiveSeedIDs(ctx context.Context, projectID int64) (map[int64]bool, error)
}

type seedCollectionRepo struct{ r *Repo }

func (r *Repo) SeedCollection() SeedCollectionRepo { return &seedCollectionRepo{r: r} }

func (c *seedCollectionRepo) CreateJob(ctx context.Context, projectID, seedID int64, kind, value string) (*SeedCollectionJob, error) {
	id := oid.NewObjectID().Hex()
	job := &SeedCollectionJob{ID: id, ProjectID: projectID, SeedID: seedID, Kind: kind, Value: value, Status: "queued"}
	_, err := c.r.pool.Exec(ctx, `
insert into seed_collection_jobs (id, project_id, seed_id, kind, value)
values ($1,$2,$3,$4,$5)`, id, projectID, seedID, kind, value)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// ClaimJob 按 ID 认领任务（queued→running 条件更新）。
// 通道消息携带具体 jobID，必须按 ID 认领：按「最旧 queued」认领会在
// 并发入队/重启恢复时与消息顺序错位，把两个任务一起永久卡死。
func (c *seedCollectionRepo) ClaimJob(ctx context.Context, id string) (*SeedCollectionJob, error) {
	job := &SeedCollectionJob{}
	err := c.r.pool.QueryRow(ctx, `
update seed_collection_jobs set status = 'running', started_at = now()
where id = $1 and status = 'queued'
returning id, project_id, seed_id, kind, value, status, found, error, created_at, started_at, finished_at`,
		id).
		Scan(&job.ID, &job.ProjectID, &job.SeedID, &job.Kind, &job.Value, &job.Status,
			&job.Found, &job.Error, &job.CreatedAt, &job.StartedAt, &job.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return job, nil
}

// ResetStaleRunning 把残留的 running 任务重置回 queued（进程崩溃/重启恢复）。
func (c *seedCollectionRepo) ResetStaleRunning(ctx context.Context) (int64, error) {
	tag, err := c.r.pool.Exec(ctx, `
update seed_collection_jobs set status = 'queued', started_at = null
where status = 'running'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ListQueuedJobIDs 按 FIFO 返回 queued 任务的 ID（启动恢复重推通道用）。
func (c *seedCollectionRepo) ListQueuedJobIDs(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := c.r.pool.Query(ctx, `
select id from seed_collection_jobs where status = 'queued'
order by created_at asc limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (c *seedCollectionRepo) FinishJob(ctx context.Context, id string, status string, found int, errMsg string) error {
	_, err := c.r.pool.Exec(ctx, `
update seed_collection_jobs set status = $2, found = $3, error = $4, finished_at = now()
where id = $1`, id, status, found, errMsg)
	return err
}

func (c *seedCollectionRepo) ListJobs(ctx context.Context, projectID int64, limit int) ([]SeedCollectionJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := c.r.pool.Query(ctx, `
select id, project_id, seed_id, kind, value, status, found, error, created_at, started_at, finished_at
from seed_collection_jobs where project_id = $1
order by created_at desc limit $2`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SeedCollectionJob{}
	for rows.Next() {
		var j SeedCollectionJob
		if err := rows.Scan(&j.ID, &j.ProjectID, &j.SeedID, &j.Kind, &j.Value, &j.Status,
			&j.Found, &j.Error, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (c *seedCollectionRepo) CountActive(ctx context.Context, projectID int64) (int64, error) {
	var n int64
	err := c.r.pool.QueryRow(ctx, `
select count(*) from seed_collection_jobs
where project_id = $1 and status in ('queued','running')`, projectID).Scan(&n)
	return n, err
}

// ListActiveSeedIDs 项目内仍处于 queued/running 的种子 ID 集合。
// 入队去重用：不受历史作业量影响，比翻最近 N 条作业再过滤可靠。
func (c *seedCollectionRepo) ListActiveSeedIDs(ctx context.Context, projectID int64) (map[int64]bool, error) {
	rows, err := c.r.pool.Query(ctx, `
select distinct seed_id from seed_collection_jobs
where project_id = $1 and status in ('queued','running')`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// 发现轮历史（巡航状态可见性）
// ---------------------------------------------------------------------------

type DiscoveryRun struct {
	ID          int64     `json:"id"`
	ProjectID   int64     `json:"project_id"`
	RanAt       time.Time `json:"ran_at"`
	FromCTLog   int       `json:"from_ctlog"`
	FromEngines int       `json:"from_engines"`
	NewCount    int       `json:"new_count"`
	Error       string    `json:"error"`
}

func (r *Repo) RecordDiscoveryRun(ctx context.Context, projectID int64, fromCT, fromEngines, newCount int, errMsg string) error {
	_, err := r.pool.Exec(ctx, `
insert into discovery_runs (project_id, from_ctlog, from_engines, new_count, error)
values ($1,$2,$3,$4,$5)`, projectID, fromCT, fromEngines, newCount, errMsg)
	return err
}

func (r *Repo) LastDiscoveryRun(ctx context.Context, projectID int64) (*DiscoveryRun, error) {
	d := &DiscoveryRun{}
	err := r.pool.QueryRow(ctx, `
select id, project_id, ran_at, from_ctlog, from_engines, new_count, coalesce(error,'')
from discovery_runs where project_id = $1 order by ran_at desc limit 1`, projectID).
		Scan(&d.ID, &d.ProjectID, &d.RanAt, &d.FromCTLog, &d.FromEngines, &d.NewCount, &d.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}
