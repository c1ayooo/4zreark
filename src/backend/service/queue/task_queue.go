package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/oid"
)

// TaskQueue 通用任务队列。
//
// 存储从 Redis 换到了 PostgreSQL 的 task_jobs 表（kind='job'），
// 对外暴露的方法与返回结构保持不变，/api/queue 那组接口因此不受影响。
// 与扫描任务的区别：扫描作业 task_id 指向 tasks 表，这里的作业不关联 tasks。
type TaskQueue struct {
	jobs     repo.JobRepo
	workers  int
	handlers map[string]TaskHandler

	handlersMu sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup

	taskTimeout time.Duration
	maxRetries  int
	lease       time.Duration
}

// Task 任务定义
type Task struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Payload     map[string]interface{} `json:"payload"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time              `json:"created_at"`
	ScheduledAt time.Time              `json:"scheduled_at,omitempty"`
	StartedAt   time.Time              `json:"started_at,omitempty"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	Retries     int                    `json:"retries"`
	MaxRetries  int                    `json:"max_retries"`
	Status      TaskStatus             `json:"status"`
	Result      interface{}            `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	WorkerID    string                 `json:"worker_id,omitempty"`
}

// TaskStatus 任务状态。取值与改造前一致，前端按这些字符串渲染。
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusScheduled  TaskStatus = "scheduled"
	TaskStatusProcessing TaskStatus = "processing"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusRetrying   TaskStatus = "retrying"
)

// TaskHandler 任务处理器
type TaskHandler func(ctx context.Context, task *Task) (interface{}, error)

// TaskResult 任务结果
type TaskResult struct {
	TaskID      string      `json:"task_id"`
	Status      TaskStatus  `json:"status"`
	Result      interface{} `json:"result,omitempty"`
	Error       string      `json:"error,omitempty"`
	CompletedAt time.Time   `json:"completed_at"`
}

// QueueConfig 队列配置
type QueueConfig struct {
	QueueName   string
	Workers     int
	TaskTimeout time.Duration
	MaxRetries  int
}

// DefaultQueueConfig 默认配置
func DefaultQueueConfig() *QueueConfig {
	return &QueueConfig{
		QueueName:   "moon-gazing-tower",
		Workers:     10,
		TaskTimeout: 30 * time.Minute,
		MaxRetries:  3,
	}
}

// NewTaskQueue 创建任务队列。数据层未就绪时返回错误。
func NewTaskQueue(config *QueueConfig) (*TaskQueue, error) {
	if config == nil {
		config = DefaultQueueConfig()
	}
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	if config.Workers <= 0 {
		config.Workers = 10
	}
	if config.TaskTimeout <= 0 {
		config.TaskTimeout = 30 * time.Minute
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}

	return &TaskQueue{
		jobs:        r.Jobs(),
		workers:     config.Workers,
		handlers:    make(map[string]TaskHandler),
		stopCh:      make(chan struct{}),
		taskTimeout: config.TaskTimeout,
		maxRetries:  config.MaxRetries,
		// 租约给执行时长的两倍，配合 reaper 兜住进程崩溃
		lease: 2 * config.TaskTimeout,
	}, nil
}

// RegisterHandler 注册任务处理器
func (q *TaskQueue) RegisterHandler(taskType string, handler TaskHandler) {
	q.handlersMu.Lock()
	defer q.handlersMu.Unlock()
	q.handlers[taskType] = handler
}

// Start 启动工作者
func (q *TaskQueue) Start() {
	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go q.worker(fmt.Sprintf("queue-worker-%d", i))
	}
	log.Printf("[TaskQueue] Started %d workers (postgres backed)", q.workers)
}

// Stop 停止队列
func (q *TaskQueue) Stop() {
	close(q.stopCh)
	q.wg.Wait()
	log.Println("[TaskQueue] Stopped")
}

// payloadEnvelope 是 task_jobs.payload 里存的通用队列作业结构。
type payloadEnvelope struct {
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

// checkpointEnvelope 是 task_jobs.checkpoint 里存的执行结果。
type checkpointEnvelope struct {
	Result      interface{} `json:"result"`
	LastError   string      `json:"last_error"`
	Status      string      `json:"status"`
	CompletedAt time.Time   `json:"completed_at"`
}

func (q *TaskQueue) enqueue(ctx context.Context, taskType string, payload map[string]interface{}, priority int, delay time.Duration) (*Task, error) {
	// task_id 留零值：通用队列作业不对应 tasks 表记录，只是占位满足 NOT NULL
	jobID, err := q.jobs.Enqueue(ctx, repo.EnqueueJobInput{
		TaskID:      oid.NilObjectID.Hex(),
		Kind:        repo.JobKindJob,
		Priority:    priority,
		Payload:     payloadEnvelope{Type: taskType, Payload: payload},
		MaxAttempts: q.maxRetries,
		ScheduledAt: timeOrZero(delay),
	})
	if err != nil {
		return nil, err
	}

	status := TaskStatusPending
	if delay > 0 {
		status = TaskStatusScheduled
	}

	return &Task{
		ID:          strconv.FormatInt(jobID, 10),
		Type:        taskType,
		Payload:     payload,
		Priority:    priority,
		CreatedAt:   time.Now(),
		ScheduledAt: timeOrZero(delay),
		Status:      status,
		MaxRetries:  q.maxRetries,
	}, nil
}

func timeOrZero(delay time.Duration) time.Time {
	if delay <= 0 {
		return time.Time{}
	}
	return time.Now().Add(delay)
}

// Enqueue 添加任务到队列
func (q *TaskQueue) Enqueue(ctx context.Context, taskType string, payload map[string]interface{}) (*Task, error) {
	return q.enqueue(ctx, taskType, payload, 0, 0)
}

// EnqueueWithPriority 添加带优先级的任务
func (q *TaskQueue) EnqueueWithPriority(ctx context.Context, taskType string, payload map[string]interface{}, priority int) (*Task, error) {
	return q.enqueue(ctx, taskType, payload, priority, 0)
}

// Schedule 调度延迟任务
func (q *TaskQueue) Schedule(ctx context.Context, taskType string, payload map[string]interface{}, delay time.Duration) (*Task, error) {
	return q.enqueue(ctx, taskType, payload, 0, delay)
}

func decodeEnvelope(b []byte) payloadEnvelope {
	var env payloadEnvelope
	_ = json.Unmarshal(b, &env)
	return env
}

func decodeCheckpoint(b []byte) checkpointEnvelope {
	var env checkpointEnvelope
	_ = json.Unmarshal(b, &env)
	return env
}

// taskFromJob 把库里的作业映射回对外的 Task 结构。
func taskFromJob(j *repo.Job) *Task {
	env := decodeEnvelope(j.Payload)
	cp := decodeCheckpoint(j.Checkpoint)

	var status TaskStatus
	switch j.Status {
	case repo.JobQueued:
		if j.ScheduledAt.After(time.Now()) {
			status = TaskStatusScheduled
		} else {
			status = TaskStatusPending
		}
	case repo.JobRunning:
		status = TaskStatusProcessing
	case repo.JobDone:
		status = TaskStatusCompleted
	default: // failed / dead
		status = TaskStatusFailed
	}

	t := &Task{
		ID:          strconv.FormatInt(j.ID, 10),
		Type:        env.Type,
		Payload:     env.Payload,
		Priority:    j.Priority,
		CreatedAt:   j.CreatedAt,
		ScheduledAt: j.ScheduledAt,
		Retries:     j.Attempts,
		MaxRetries:  j.MaxAttempts,
		Status:      status,
		Result:      cp.Result,
		Error:       cp.LastError,
		WorkerID:    j.WorkerID,
	}
	if j.Status == repo.JobRunning || j.Status == repo.JobDone {
		t.StartedAt = j.UpdatedAt
	}
	if j.Status == repo.JobDone || j.Status == repo.JobDead {
		t.CompletedAt = cp.CompletedAt
	}
	if j.Status == repo.JobQueued && j.Attempts > 0 {
		t.Status = TaskStatusRetrying
	}
	return t
}

// worker 工作者循环
func (q *TaskQueue) worker(workerID string) {
	defer q.wg.Done()

	backoff := 200 * time.Millisecond
	for {
		select {
		case <-q.stopCh:
			return
		default:
		}

		job, err := q.jobs.ClaimGeneric(context.Background(), workerID, q.lease)
		if err != nil {
			log.Printf("[%s] Claim error: %v", workerID, err)
			time.Sleep(time.Second)
			continue
		}
		if job == nil {
			// 队列空：退避到 1s 上限，避免空转压着数据库
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 200 * time.Millisecond

		q.processJob(workerID, job)
	}
}

// processJob 执行一条领取到的作业
func (q *TaskQueue) processJob(workerID string, job *repo.Job) {
	task := taskFromJob(job)
	task.Status = TaskStatusProcessing
	task.WorkerID = workerID

	q.handlersMu.RLock()
	handler, ok := q.handlers[task.Type]
	q.handlersMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), q.taskTimeout)
	defer cancel()

	if !ok {
		q.failJob(ctx, job.ID, task, fmt.Errorf("no handler for task type: %s", task.Type))
		return
	}

	result, err := handler(ctx, task)
	if err != nil {
		q.failJob(ctx, job.ID, task, err)
		return
	}

	if err := q.jobs.Complete(ctx, job.ID, checkpointEnvelope{
		Result:      result,
		Status:      string(TaskStatusCompleted),
		CompletedAt: time.Now(),
	}); err != nil {
		log.Printf("[%s] Complete job %d error: %v", workerID, job.ID, err)
	}
	log.Printf("[%s] Job %d (%s) completed", workerID, job.ID, task.Type)
}

// failJob 失败重试：未超次数按指数退避回队列，超了进死信（status='dead'）。
func (q *TaskQueue) failJob(ctx context.Context, jobID int64, task *Task, err error) {
	backoff := time.Duration((task.Retries+1)*(task.Retries+1)) * time.Second
	status, rerr := q.jobs.Retry(ctx, jobID, err.Error(), backoff)
	if rerr != nil {
		log.Printf("[TaskQueue] Retry job %d error: %v", jobID, rerr)
	}
	log.Printf("[TaskQueue] Job %d (%s) failed -> %s: %v", jobID, task.Type, status, err)
}

// GetResult 获取任务结果
func (q *TaskQueue) GetResult(ctx context.Context, taskID string) (*TaskResult, error) {
	job, err := q.jobByID(ctx, taskID)
	if err != nil {
		return nil, err
	}
	if job.Status != repo.JobDone && job.Status != repo.JobDead {
		return nil, errors.New("任务结果不存在或已过期")
	}

	cp := decodeCheckpoint(job.Checkpoint)
	status := TaskStatusCompleted
	if job.Status == repo.JobDead {
		status = TaskStatusFailed
	}
	return &TaskResult{
		TaskID:      taskID,
		Status:      status,
		Result:      cp.Result,
		Error:       cp.LastError,
		CompletedAt: cp.CompletedAt,
	}, nil
}

func (q *TaskQueue) jobByID(ctx context.Context, taskID string) (*repo.Job, error) {
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil {
		return nil, errors.New("无效的任务ID")
	}
	job, err := q.jobs.GetByID(ctx, id)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, errors.New("任务不存在")
	}
	return job, err
}

// GetStats 获取队列统计
func (q *TaskQueue) GetStats(ctx context.Context) (map[string]interface{}, error) {
	counts, err := q.jobs.Stats(ctx, repo.JobKindJob)
	if err != nil {
		return nil, err
	}
	scheduled, err := q.jobs.CountScheduled(ctx, repo.JobKindJob)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"pending":     counts[repo.JobQueued] - scheduled,
		"scheduled":   scheduled,
		"processing":  counts[repo.JobRunning],
		"dead_letter": counts[repo.JobDead],
		"workers":     q.workers,
	}, nil
}

// GetPendingTasks 获取待处理任务
func (q *TaskQueue) GetPendingTasks(ctx context.Context, limit int64) ([]*Task, error) {
	jobs, err := q.jobs.List(ctx, repo.JobKindJob, repo.JobQueued, int(limit))
	if err != nil {
		return nil, err
	}
	return tasksFromJobs(jobs), nil
}

// GetProcessingTasks 获取处理中的任务
func (q *TaskQueue) GetProcessingTasks(ctx context.Context) ([]*Task, error) {
	jobs, err := q.jobs.List(ctx, repo.JobKindJob, repo.JobRunning, 1000)
	if err != nil {
		return nil, err
	}
	return tasksFromJobs(jobs), nil
}

// GetDeadLetterTasks 获取死信队列任务
func (q *TaskQueue) GetDeadLetterTasks(ctx context.Context, limit int64) ([]*Task, error) {
	jobs, err := q.jobs.List(ctx, repo.JobKindJob, repo.JobDead, int(limit))
	if err != nil {
		return nil, err
	}
	return tasksFromJobs(jobs), nil
}

func tasksFromJobs(jobs []*repo.Job) []*Task {
	tasks := make([]*Task, 0, len(jobs))
	for _, j := range jobs {
		tasks = append(tasks, taskFromJob(j))
	}
	return tasks
}

// RetryDeadLetter 重试死信队列任务
func (q *TaskQueue) RetryDeadLetter(ctx context.Context, taskID string) error {
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil {
		return errors.New("task not found in dead letter queue")
	}
	if err := q.jobs.RetryDead(ctx, id); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("task not found in dead letter queue")
		}
		return err
	}
	return nil
}

// ClearDeadLetter 清空死信队列
func (q *TaskQueue) ClearDeadLetter(ctx context.Context) error {
	return q.jobs.ClearDead(ctx, repo.JobKindJob)
}

// GetWorkerStatus 获取Worker状态
func (q *TaskQueue) GetWorkerStatus(ctx context.Context) (map[string]interface{}, error) {
	counts, err := q.jobs.Stats(ctx, repo.JobKindJob)
	if err != nil {
		return nil, err
	}
	workers, err := q.jobs.ActiveWorkers(ctx, repo.JobKindJob)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"active":  counts[repo.JobRunning],
		"total":   q.workers,
		"workers": workers,
	}, nil
}
