package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
)

// 扫描作业队列的 River 定义。
const (
	ScanQueueName = "scan"
	ScanJobKind   = "scan_task"
	// scanJobTimeout 要和流水线自身的 24h 上限保持一致；River 到点会取消 Work 的 ctx。
	scanJobTimeout = 24 * time.Hour
)

// ScanJobArgs 是扫描作业的唯一参数：task_id 指向 tasks 表。
type ScanJobArgs struct {
	TaskID string `json:"task_id" river:"unique"`
}

func (ScanJobArgs) Kind() string { return ScanJobKind }

// scanJobWorker 把 River 作业转交给 TaskExecutor。
type scanJobWorker struct {
	river.WorkerDefaults[ScanJobArgs]
	executor *TaskExecutor
}

func (w *scanJobWorker) Work(ctx context.Context, job *river.Job[ScanJobArgs]) error {
	return w.executor.RunScanJob(ctx, job.Args.TaskID, job.ID)
}

// ScanQueue 是 master/worker 共用的 River 客户端。
// master 只 Insert（insert-only client），worker 额外启动 Work 循环。
type ScanQueue struct {
	client     *river.Client[pgx.Tx]
	pool       *pgxpool.Pool
	workerMode bool
}

var (
	scanQueueMu sync.RWMutex
	scanQueue   *ScanQueue
)

// SetDefaultScanQueue 设置进程级扫描队列，TaskService 入队时使用。
func SetDefaultScanQueue(q *ScanQueue) {
	scanQueueMu.Lock()
	scanQueue = q
	scanQueueMu.Unlock()
}

// DefaultScanQueue 返回进程级扫描队列；未初始化时为 nil。
func DefaultScanQueue() *ScanQueue {
	scanQueueMu.RLock()
	defer scanQueueMu.RUnlock()
	return scanQueue
}

// NewScanQueue 初始化 River（含表结构迁移）并创建客户端。
// workerMode=false 时只创建 insert-only 客户端，不启动 Work 循环。
func NewScanQueue(ctx context.Context, pool *pgxpool.Pool, workers int, executor *TaskExecutor, workerMode bool) (*ScanQueue, error) {
	if pool == nil {
		return nil, errors.New("扫描队列缺少 PostgreSQL 连接池")
	}
	if workerMode && executor == nil {
		return nil, errors.New("worker 模式需要 TaskExecutor")
	}
	if workers < 1 {
		workers = 1
	}
	if workers > MaxNodeWorkers {
		workers = MaxNodeWorkers
	}

	driver := riverpgxv5.New(pool)
	migrator, err := rivermigrate.New(driver, nil)
	if err != nil {
		return nil, fmt.Errorf("初始化 River 迁移器失败: %w", err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return nil, fmt.Errorf("执行 River 迁移失败: %w", err)
	}

	cfg := &river.Config{
		MaxAttempts:          3,
		JobTimeout:           scanJobTimeout,
		RescueStuckJobsAfter: scanJobTimeout + time.Hour,
		SoftStopTimeout:      30 * time.Second,
	}
	if workerMode {
		riverWorkers := river.NewWorkers()
		river.AddWorker(riverWorkers, &scanJobWorker{executor: executor})
		cfg.Workers = riverWorkers
		cfg.Queues = map[string]river.QueueConfig{
			ScanQueueName: {MaxWorkers: workers},
		}
	}

	client, err := river.NewClient(driver, cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 River 客户端失败: %w", err)
	}

	return &ScanQueue{client: client, pool: pool, workerMode: workerMode}, nil
}

// Start 启动 Work 循环。insert-only 客户端不调用。
func (q *ScanQueue) Start(ctx context.Context) error {
	if !q.workerMode {
		return nil
	}
	if err := q.client.Start(ctx); err != nil {
		return fmt.Errorf("启动 River 客户端失败: %w", err)
	}
	log.Printf("[ScanQueue] River 已启动（queue=%s）", ScanQueueName)
	return nil
}

// Stop 停止拉取新作业，等待在跑作业收尾；超时由 SoftStopTimeout 升级为取消。
func (q *ScanQueue) Stop(ctx context.Context) error {
	if !q.workerMode {
		return nil
	}
	return q.client.Stop(ctx)
}

// Enqueue 把一个扫描任务放进 River 队列。
// 同一个 task 的活跃作业按 args 去重，重复入队不会产生两条并发作业。
func (q *ScanQueue) Enqueue(ctx context.Context, taskID string, priority int) error {
	if q == nil || q.client == nil {
		return errors.New("扫描队列未初始化")
	}
	_, err := q.client.Insert(ctx, ScanJobArgs{TaskID: taskID}, &river.InsertOpts{
		Queue:       ScanQueueName,
		Priority:    riverPriority(priority),
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRetryable,
				rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("任务入队失败: %w", err)
	}
	return nil
}

// CancelQueued 取消某个任务还没开始执行的 River 作业（暂停/取消任务时调用）。
func (q *ScanQueue) CancelQueued(ctx context.Context, taskID string) (int, error) {
	if q == nil || q.client == nil {
		return 0, nil
	}
	params := river.NewJobListParams().
		Kinds(ScanJobKind).
		States(
			rivertype.JobStateAvailable,
			rivertype.JobStatePending,
			rivertype.JobStateRetryable,
			rivertype.JobStateScheduled,
		).
		Where("args->>'task_id' = @task_id", river.NamedArgs{"task_id": taskID}).
		First(1000)

	res, err := q.client.JobList(ctx, params)
	if err != nil {
		return 0, fmt.Errorf("查询排队作业失败: %w", err)
	}

	cancelled := 0
	for _, job := range res.Jobs {
		if _, err := q.client.JobCancel(ctx, job.ID); err != nil {
			log.Printf("[ScanQueue] 取消作业 %d（task=%s）失败: %v", job.ID, taskID, err)
			continue
		}
		cancelled++
	}
	return cancelled, nil
}

// MigrateLegacy 把旧 task_jobs 里的扫描作业迁移到 River，只在控制面启动时调用。
// 只迁移排队中或租约已过期的 running 作业，避免和仍在运行的旧进程抢任务。
func (q *ScanQueue) MigrateLegacy(ctx context.Context) error {
	if q == nil || q.pool == nil {
		return nil
	}
	rows, err := q.pool.Query(ctx,
		`select j.id, j.task_id, j.priority, coalesce(t.status, '')
		   from task_jobs j
		   left join tasks t on t.id = j.task_id
		  where j.kind = 'scan'
		    and (j.status = 'queued' or (j.status = 'running' and j.lease_expires_at < now()))
		  order by j.id`)
	if err != nil {
		return fmt.Errorf("读取旧扫描队列失败: %w", err)
	}
	defer rows.Close()

	type legacyJob struct {
		id       int64
		taskID   string
		priority int
		status   string
	}
	var legacy []legacyJob
	for rows.Next() {
		var j legacyJob
		if err := rows.Scan(&j.id, &j.taskID, &j.priority, &j.status); err != nil {
			return fmt.Errorf("扫描旧作业失败: %w", err)
		}
		legacy = append(legacy, j)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	migrated := 0
	for _, j := range legacy {
		if j.status == string(models.TaskStatusPending) || j.status == string(models.TaskStatusRunning) {
			if err := q.Enqueue(ctx, j.taskID, j.priority); err != nil {
				log.Printf("[ScanQueue] 迁移旧作业 %d（task=%s）失败，保留原记录: %v", j.id, j.taskID, err)
				continue
			}
		}
		if _, err := q.pool.Exec(ctx,
			`update task_jobs
			    set status = 'done', worker_id = null, lease_expires_at = null,
			        checkpoint = checkpoint || jsonb_build_object('last_error', '已迁移到 River'),
			        updated_at = now()
			  where id = $1 and kind = 'scan'`, j.id); err != nil {
			log.Printf("[ScanQueue] 标记旧作业 %d 已迁移失败: %v", j.id, err)
			continue
		}
		migrated++
	}
	if migrated > 0 {
		log.Printf("[ScanQueue] 已把 %d 条旧 task_jobs 扫描作业迁移到 River", migrated)
	}
	return nil
}

// riverPriority 把旧的 0-255 优先级映射到 River 的 1（最高）~4（最低）。
func riverPriority(p int) int {
	switch {
	case p >= 200:
		return 1
	case p >= 100:
		return 2
	case p >= 50:
		return 3
	default:
		return 4
	}
}
