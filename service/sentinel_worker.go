package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
)

// 提交哨兵的 River 队列（v0.3 §6）。
const (
	SentinelCollectQueueName = "sentinel_collect"
	SentinelJudgeQueueName   = "sentinel_judge"
	SentinelCollectJobKind   = "sentinel_collect_repo"
	SentinelJudgeJobKind     = "sentinel_judge_commit"
)

// SentinelCollectArgs 采集一个仓库。
type SentinelCollectArgs struct {
	RepoID string `json:"repo_id" river:"unique"`
}

// Kind 实现 river.JobArgs。
func (SentinelCollectArgs) Kind() string { return SentinelCollectJobKind }

// SentinelJudgeArgs 判定一条提交。
type SentinelJudgeArgs struct {
	CommitID int64 `json:"commit_id" river:"unique"`
}

// Kind 实现 river.JobArgs。
func (SentinelJudgeArgs) Kind() string { return SentinelJudgeJobKind }

type sentinelCollectWorker struct {
	river.WorkerDefaults[SentinelCollectArgs]
	source *SentinelSource
}

func (w *sentinelCollectWorker) Work(ctx context.Context, job *river.Job[SentinelCollectArgs]) error {
	if err := sentinelGate.Acquire(ctx); err != nil {
		return sentinelJobError(err)
	}
	defer sentinelGate.Release()
	_, err := w.source.Collect(ctx, job.Args.RepoID)
	return sentinelJobError(err)
}

type sentinelJudgeWorker struct {
	river.WorkerDefaults[SentinelJudgeArgs]
	judge *SentinelJudge
}

func (w *sentinelJudgeWorker) Work(ctx context.Context, job *river.Job[SentinelJudgeArgs]) error {
	if err := sentinelGate.Acquire(ctx); err != nil {
		return sentinelJobError(err)
	}
	defer sentinelGate.Release()
	_, err := w.judge.Judge(ctx, job.Args.CommitID)
	return sentinelJobError(err)
}

// sentinelJobError 把业务错误映射为 River 的失败语义：
//   - 限流 → 5 分钟后重试（JobSnooze）
//   - 配置错误 / 模型永久错误 → 不再重试（JobCancel）
//   - 其它 → River 默认退避
func sentinelJobError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, llm.ErrRateLimited):
		return river.JobSnooze(5 * time.Minute)
	case errors.Is(err, errSentinelConfig), errors.Is(err, llm.ErrPermanent):
		return river.JobCancel(err)
	default:
		return err
	}
}

var (
	sentinelQueueMu sync.RWMutex
	sentinelQueue   *SentinelQueue
)

// SetDefaultSentinelQueue 设置进程级提交哨兵队列，供 handler 触发采集/判定。
func SetDefaultSentinelQueue(q *SentinelQueue) {
	sentinelQueueMu.Lock()
	sentinelQueue = q
	sentinelQueueMu.Unlock()
}

// DefaultSentinelQueue 返回进程级队列；未初始化（功能关闭）时为 nil。
func DefaultSentinelQueue() *SentinelQueue {
	sentinelQueueMu.RLock()
	defer sentinelQueueMu.RUnlock()
	return sentinelQueue
}

// SentinelQueue 是提交哨兵的 River 客户端。
//
// 它与 ScanQueue 各自持有一个 *river.Client：两者的队列集合完全不同
// （scan 与 sentinel_collect/sentinel_judge），共用同一张 river_job 表与同一个连接池，
// 各自只轮询自己的队列，不会抢对方的作业；River 迁移重复执行是幂等的。
type SentinelQueue struct {
	client     *river.Client[pgx.Tx]
	pool       *pgxpool.Pool
	workerMode bool
	cfg        config.SentinelConfig
}

// NewSentinelQueue 初始化 River 客户端；workerMode=false 时仅能入队（控制面只跑采集调度时用）。
func NewSentinelQueue(ctx context.Context, pool *pgxpool.Pool, cfg config.SentinelConfig, source *SentinelSource, judge *SentinelJudge, workerMode bool) (*SentinelQueue, error) {
	if pool == nil {
		return nil, errors.New("提交哨兵队列缺少 PostgreSQL 连接池")
	}
	cfg.Normalize()

	driver := riverpgxv5.New(pool)
	migrator, err := rivermigrate.New(driver, nil)
	if err != nil {
		return nil, fmt.Errorf("初始化提交哨兵 River 迁移器失败: %w", err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return nil, fmt.Errorf("执行提交哨兵 River 迁移失败: %w", err)
	}

	riverCfg := &river.Config{
		MaxAttempts:          3,
		JobTimeout:           30 * time.Minute,
		RescueStuckJobsAfter: 30 * time.Minute,
		SoftStopTimeout:      30 * time.Second,
	}
	if workerMode {
		if source == nil || judge == nil {
			return nil, errors.New("worker 模式需要采集与判定服务")
		}
		workers := river.NewWorkers()
		river.AddWorker(workers, &sentinelCollectWorker{source: source})
		river.AddWorker(workers, &sentinelJudgeWorker{judge: judge})
		river.AddWorker(workers, &sentinelArtifactsWorker{judge: judge})
		// repro worker 仅在 pocsmith 进程消费；主进程注册哑实现只为通过
		// Insert 的 kind 注册校验（sentinel_repro 队列不在本进程 Queues 里，
		// 永远不会被本进程拉取执行）。
		river.AddWorker(workers, &sentinelReproWorker{})
		river.AddWorker(workers, &sentinelPocVerifyWorker{})
		riverCfg.Workers = workers
		riverCfg.Queues = map[string]river.QueueConfig{
			SentinelCollectQueueName:   {MaxWorkers: cfg.CollectWorkers},
			SentinelJudgeQueueName:     {MaxWorkers: cfg.JudgeWorkers},
			SentinelArtifactsQueueName: {MaxWorkers: 1}, // LLM 产物流水线串行，控制成本与速率
		}
	}

	client, err := river.NewClient(driver, riverCfg)
	if err != nil {
		return nil, fmt.Errorf("创建提交哨兵 River 客户端失败: %w", err)
	}
	return &SentinelQueue{client: client, pool: pool, workerMode: workerMode, cfg: cfg}, nil
}

// Start 启动 Work 循环（非 worker 模式为空操作）。
func (q *SentinelQueue) Start(ctx context.Context) error {
	if q == nil || !q.workerMode {
		return nil
	}
	if err := q.client.Start(ctx); err != nil {
		return fmt.Errorf("启动提交哨兵 River 客户端失败: %w", err)
	}
	// 动态并发闸 watchdog：按内存水位运行时降档 2→1→0（可慢不可挂）。
	StartSentinelGateWatchdog(ctx)
	log.Printf("[Sentinel] River 已启动（queues=%s,%s,%s collect=%d judge=%d artifacts=1）",
		SentinelCollectQueueName, SentinelJudgeQueueName, SentinelArtifactsQueueName, q.cfg.CollectWorkers, q.cfg.JudgeWorkers)

	// 启动回填：产物流水线上线前的存量高危发现（判定命中时流水线还没实现，
	// 不会自动补跑）在这里一次性入队。入队幂等（river unique + 深审产物缺失
	// 判断），重复启动不会重复生成。
	go func() {
		ctx := context.Background()
		if n, err := BackfillHighRiskArtifacts(ctx, 200); err != nil {
			log.Printf("[Sentinel] 存量产物流水线回填失败: %v", err)
		} else if n > 0 {
			log.Printf("[Sentinel] 存量产物流水线回填：已入队 %d 条", n)
		}
	}()
	return nil
}

// Stop 停止拉取并等待在跑作业收尾。
func (q *SentinelQueue) Stop(ctx context.Context) error {
	if q == nil || !q.workerMode {
		return nil
	}
	return q.client.Stop(ctx)
}

// EnqueueCollect 把仓库采集放进队列；同一仓库的活跃作业按参数去重。
func (q *SentinelQueue) EnqueueCollect(ctx context.Context, repoID string) error {
	if q == nil || q.client == nil {
		return errors.New("提交哨兵队列未初始化")
	}
	_, err := q.client.Insert(ctx, SentinelCollectArgs{RepoID: repoID}, &river.InsertOpts{
		Queue:       SentinelCollectQueueName,
		MaxAttempts: 3,
		UniqueOpts:  sentinelUniqueOpts(),
	})
	if err != nil {
		return fmt.Errorf("采集任务入队失败: %w", err)
	}
	return nil
}

// Sentinel 判定队列的 River 优先级分层（River：1 最高、4 最低，默认 1）。
// 人等着的（手动重判/上传导入）排最高；预评分高的批量提交次之；
// 大批量低分提交降到最低，避免淹没交互请求。
const (
	SentinelJudgePriorityManual = 1 // 手动重判 / 上传导入等人在等的
	SentinelJudgePriorityHot    = 2 // 批量里预评分高的（疑似安全修复主题）
	SentinelJudgePriorityBulk   = 4 // 批量低分提交，慢慢消化
)

// EnqueueJudge 把提交判定放进队列（人工触发路径，最高优先级）。
func (q *SentinelQueue) EnqueueJudge(ctx context.Context, commitID int64) error {
	return q.EnqueueJudgePriority(ctx, commitID, SentinelJudgePriorityManual)
}

// EnqueueJudgePriority 按优先级入队判定。
func (q *SentinelQueue) EnqueueJudgePriority(ctx context.Context, commitID int64, priority int) error {
	if q == nil || q.client == nil {
		return errors.New("提交哨兵队列未初始化")
	}
	_, err := q.client.Insert(ctx, SentinelJudgeArgs{CommitID: commitID}, &river.InsertOpts{
		Queue:       SentinelJudgeQueueName,
		MaxAttempts: 3,
		Priority:    priority,
		UniqueOpts:  sentinelUniqueOpts(),
	})
	if err != nil {
		return fmt.Errorf("判定任务入队失败: %w", err)
	}
	return nil
}

func sentinelUniqueOpts() river.UniqueOpts {
	return river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable,
			rivertype.JobStatePending,
			rivertype.JobStateRetryable,
			rivertype.JobStateRunning,
			rivertype.JobStateScheduled,
		},
	}
}

// RunScheduler 周期调度：到点的仓库入采集队列，待判定的提交入判定队列。
// ctx 取消即退出（main 关停链会取消）。
func (q *SentinelQueue) RunScheduler(ctx context.Context) {
	if q == nil {
		return
	}
	interval := time.Duration(q.cfg.CollectIntervalMin) * time.Minute
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	q.scheduleOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.scheduleOnce(ctx)
		}
	}
}

func (q *SentinelQueue) scheduleOnce(ctx context.Context) {
	store := repo.Default().Sentinel()

	due, err := store.ListDueRepos(ctx, 20)
	if err != nil {
		log.Printf("[Sentinel] 查询待采集仓库失败: %v", err)
	} else {
		for _, r := range due {
			if err := q.EnqueueCollect(ctx, r.ID); err != nil {
				log.Printf("[Sentinel] 仓库 %s 入队失败: %v", r.ID, err)
			}
		}
	}

	pending, err := store.ListPendingCommits(ctx, "", q.cfg.MaxCommitsPerRun)
	if err != nil {
		log.Printf("[Sentinel] 查询待判定提交失败: %v", err)
		return
	}
	for _, c := range pending {
		// 预评分高的提交（标题/路径像安全修复主题）排更高优先级，
		// 让疑似高危的先判定；评分只是启发式，不据此丢弃任何提交。
		priority := SentinelJudgePriorityBulk
		if c.Score >= 5 {
			priority = SentinelJudgePriorityHot
		}
		if err := q.EnqueueJudgePriority(ctx, c.ID, priority); err != nil {
			log.Printf("[Sentinel] 提交 %d 入队失败: %v", c.ID, err)
		}
	}
}

// ---- pocsmith 差分复现（v0.3 §7.6-7.9）----
//
// 队列与采集/判定同库不同名；worker 只在独立进程 pocsmith（cmd/pocsmith）里
// 注册——docker build/run 吃满 CPU/磁盘，不能和控制面抢资源（文档 §3.0 决策）。

const (
	SentinelReproQueueName = "sentinel_repro"
	SentinelReproJobKind   = "sentinel_repro_finding"
)

// SentinelReproArgs 复现一条发现。
type SentinelReproArgs struct {
	FindingID int64 `json:"finding_id" river:"unique"`
}

// Kind 实现 river.JobArgs。
func (SentinelReproArgs) Kind() string { return SentinelReproJobKind }

type sentinelReproWorker struct {
	river.WorkerDefaults[SentinelReproArgs]
	repro *ReproService
}

func (w *sentinelReproWorker) Work(ctx context.Context, job *river.Job[SentinelReproArgs]) error {
	if w.repro == nil {
		// 主进程的哑 worker 防御：sentinel_repro 队列不在其 Queues 里，理论不可达。
		return errors.New("repro worker 归属 pocsmith 进程，本进程不应执行该作业")
	}
	err := w.repro.Repro(ctx, job.Args.FindingID)
	// 输入/环境问题（缺 PoC、计划非法、docker 不可用）不重试：再跑结果一样。
	if errors.Is(err, errSentinelReproInput) {
		return river.JobCancel(err)
	}
	return sentinelJobError(err)
}

// NewSentinelReproClient 是 pocsmith 专用的 River 客户端：注册差分复现与
// POC 靶场验证两个 worker，消费 sentinel_repro 与 sentinel_poc_verify 队列。
// 与主进程的 SentinelQueue 共享 river_job 表，互不抢作业。
func NewSentinelReproClient(ctx context.Context, pool *pgxpool.Pool, repro *ReproService, verify *PocVerifyService) (*river.Client[pgx.Tx], error) {
	if pool == nil {
		return nil, errors.New("pocsmith 缺少 PostgreSQL 连接池")
	}
	if repro == nil {
		return nil, errors.New("pocsmith 缺少复现服务")
	}
	if verify == nil {
		return nil, errors.New("pocsmith 缺少靶场验证服务")
	}
	driver := riverpgxv5.New(pool)
	migrator, err := rivermigrate.New(driver, nil)
	if err != nil {
		return nil, fmt.Errorf("初始化 River 迁移器失败: %w", err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return nil, fmt.Errorf("执行 River 迁移失败: %w", err)
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, &sentinelReproWorker{repro: repro})
	river.AddWorker(workers, &sentinelPocVerifyWorker{verify: verify})
	client, err := river.NewClient(driver, &river.Config{
		MaxAttempts:          2,
		JobTimeout:           40 * time.Minute,
		RescueStuckJobsAfter: 30 * time.Minute,
		Workers:              workers,
		Queues: map[string]river.QueueConfig{
			SentinelReproQueueName:     {MaxWorkers: 2},
			SentinelPocVerifyQueueName: {MaxWorkers: 1}, // 容器编排重，串行执行
		},
	})
	if err != nil {
		return nil, fmt.Errorf("创建 pocsmith River 客户端失败: %w", err)
	}
	return client, nil
}

// EnqueueRepro 把发现复现放进队列（主进程控制面调用；worker 在 pocsmith）。
func (q *SentinelQueue) EnqueueRepro(ctx context.Context, findingID int64) error {
	if q == nil || q.client == nil {
		return errors.New("提交哨兵队列未初始化")
	}
	_, err := q.client.Insert(ctx, SentinelReproArgs{FindingID: findingID}, &river.InsertOpts{
		Queue:       SentinelReproQueueName,
		MaxAttempts: 2,
		UniqueOpts:  sentinelUniqueOpts(),
	})
	if err != nil {
		return fmt.Errorf("复现任务入队失败: %w", err)
	}
	return nil
}

// ---- pocsmith POC 靶场验证（Tier 3b）----
//
// python-poc verified 后自动入队（或 MCP 手动触发）：拉公开靶场镜像起隔离
// 内网靶场，PoC 打靶场判定可行性。worker 同样只在 pocsmith 进程消费。

const (
	SentinelPocVerifyQueueName = "sentinel_poc_verify"
	SentinelPocVerifyJobKind   = "sentinel_poc_verify_finding"
)

// SentinelPocVerifyArgs 靶场验证一条发现；Force 忽略已有 poc-verify 产物重跑。
type SentinelPocVerifyArgs struct {
	FindingID int64 `json:"finding_id" river:"unique"`
	Force     bool  `json:"force,omitempty"`
}

// Kind 实现 river.JobArgs。
func (SentinelPocVerifyArgs) Kind() string { return SentinelPocVerifyJobKind }

type sentinelPocVerifyWorker struct {
	river.WorkerDefaults[SentinelPocVerifyArgs]
	verify *PocVerifyService
}

func (w *sentinelPocVerifyWorker) Work(ctx context.Context, job *river.Job[SentinelPocVerifyArgs]) error {
	if w.verify == nil {
		// 主进程的哑 worker 防御：sentinel_poc_verify 队列不在其 Queues 里。
		return errors.New("poc-verify worker 归属 pocsmith 进程，本进程不应执行该作业")
	}
	err := w.verify.Verify(ctx, job.Args.FindingID, job.Args.Force)
	if errors.Is(err, errSentinelPocVerifyInput) {
		return river.JobCancel(err)
	}
	return sentinelJobError(err)
}

// EnqueuePocVerify 把靶场验证放进队列（主进程控制面调用；worker 在 pocsmith）。
func (q *SentinelQueue) EnqueuePocVerify(ctx context.Context, findingID int64, force bool) error {
	if q == nil || q.client == nil {
		return errors.New("提交哨兵队列未初始化")
	}
	_, err := q.client.Insert(ctx, SentinelPocVerifyArgs{FindingID: findingID, Force: force}, &river.InsertOpts{
		Queue:       SentinelPocVerifyQueueName,
		MaxAttempts: 2,
		UniqueOpts:  sentinelUniqueOpts(),
	})
	if err != nil {
		return fmt.Errorf("靶场验证任务入队失败: %w", err)
	}
	return nil
}
