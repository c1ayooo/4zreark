package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/scanner/scope"
	"github.com/c1ayooo/4zreark/service/notify"
	"github.com/c1ayooo/4zreark/service/pipeline"

	"github.com/riverqueue/river"
)

// ErrNoNodeAvailable 表示当前没有已连接且有容量的 worker；调用方应 snooze 而不是判失败。
var ErrNoNodeAvailable = errors.New("没有可用的扫描节点")

// NodeDispatcher 由平台侧的 WS 节点网关实现，把任务推给远程 worker。
type NodeDispatcher interface {
	Dispatch(ctx context.Context, taskID string) error
}

// taskStore 是执行器需要的任务读写能力：本地是 *TaskService，远程 worker 用 HTTP 实现。
type taskStore interface {
	GetTaskByID(taskID string) (*models.Task, error)
	UpdateTask(taskID string, updates map[string]interface{}) error
}

// resultStore 是执行器需要的结果落库能力：本地是 *ResultService，远程 worker 走 HTTP。
type resultStore interface {
	CreateResult(result *models.ScanResult) error
	CreateResultWithDedup(result *models.ScanResult) error
	UpdateSubdomainCDN(taskID, domain, cdnProvider string) error
}

// resultFlusher 由远程结果实现：批量上传，任务结束前必须 Flush。
type resultFlusher interface {
	Flush(ctx context.Context, taskID string) error
}

// assetStore 把扫描结果里的资产/路由写回平台：本地直接走 AssetService，远程走 HTTP。
type assetStore interface {
	Ingest(ctx context.Context, task *models.Task, records []repo.RawRecord) error
	SaveRoutes(ctx context.Context, task *models.Task, routes []CrawledEndpoint) error
}

type localAssetStore struct{}

func (localAssetStore) Ingest(ctx context.Context, task *models.Task, records []repo.RawRecord) error {
	if task.ProjectID <= 0 || len(records) == 0 {
		return nil
	}
	assetSvc := NewAssetService()
	const importChunk = 5000
	var totalRecords, newSites, newEndpoints int
	for start := 0; start < len(records); start += importChunk {
		end := start + importChunk
		if end > len(records) {
			end = len(records)
		}
		res, err := assetSvc.Ingest(ctx, task.ProjectID, "scan", records[start:end])
		if err != nil {
			return err
		}
		totalRecords += res.Records
		newSites += res.NewSites
		newEndpoints += res.NewEndpoints
	}
	log.Printf("[TaskExecutor] 扫描结果并入资产: 记录 %d，新站点 %d，新入口 %d（project=%d）",
		totalRecords, newSites, newEndpoints, task.ProjectID)
	return nil
}

func (localAssetStore) SaveRoutes(ctx context.Context, task *models.Task, routes []CrawledEndpoint) error {
	if len(routes) == 0 {
		return nil
	}
	sites, saved, err := NewAssetService().SaveCrawledRoutes("pipeline", routes)
	if err != nil {
		return err
	}
	if saved > 0 {
		log.Printf("[TaskExecutor] 路由入库: 站点 %d 个，路由 %d 条", sites, saved)
	}
	return nil
}

type remoteAssetStore struct{ client *RemoteClient }

func (s remoteAssetStore) Ingest(ctx context.Context, task *models.Task, records []repo.RawRecord) error {
	if len(records) == 0 {
		return nil
	}
	return s.client.PostAssets(ctx, task.ID.Hex(), records, nil)
}

func (s remoteAssetStore) SaveRoutes(ctx context.Context, task *models.Task, routes []CrawledEndpoint) error {
	if len(routes) == 0 {
		return nil
	}
	return s.client.PostAssets(ctx, task.ID.Hex(), nil, routes)
}

// runningTask 正在运行的任务信息
type runningTask struct {
	cancelFunc context.CancelFunc
	pipeline   *pipeline.StreamingPipeline
}

// MaxNodeWorkers 是节点并发上限的硬上限，防止误配把单机拖垮。
const MaxNodeWorkers = 64

// TaskExecutor 负责任务状态推进、流水线执行与本地取消。
// 扫描作业的领取/租约/重试由 River 负责；本结构不再自己轮询 task_jobs。
type TaskExecutor struct {
	taskService   taskStore
	resultService resultStore
	assets        assetStore
	jobs          repo.JobRepo
	// dispatcher 非空时，本执行器是 master：River Work 把任务推给远程 worker，而不是本地跑。
	dispatcher NodeDispatcher
	// localFallback=true 时（role=all），没有远程节点就退回本地执行。
	localFallback bool
	remote        bool
	// workers 是节点启动时的并发容量（River MaxWorkers），SetMaxTasks 不能超过它。
	workers int
	stopCh  chan struct{}
	wg      sync.WaitGroup
	// nodeID/nodeName 标识扫描作业属于哪个节点，写入 tasks.node_id。
	nodeID   string
	nodeName string
	// running 是本进程正在执行的任务数，心跳上报给节点管理页。
	running int64
	// maxTasks 是当前允许的并发上限，可由节点页在线调低。
	maxTasks atomic.Int64
	// paused=true 时不再执行新作业（管理员在节点页停用）。
	paused atomic.Bool
	// 正在运行的任务，用于取消
	runningTasks map[string]*runningTask
	runningMutex sync.RWMutex
}

// NewTaskExecutor 创建任务执行器。workers=0 表示只跑状态监控/租约回收（role=master）。
func NewTaskExecutor(workers int) *TaskExecutor {
	if workers < 0 {
		workers = 0
	}
	if workers > MaxNodeWorkers {
		workers = MaxNodeWorkers
	}
	e := &TaskExecutor{
		taskService:   NewTaskService(),
		resultService: NewResultService(),
		assets:        localAssetStore{},
		workers:       workers,
		stopCh:        make(chan struct{}),
		runningTasks:  make(map[string]*runningTask),
	}
	e.maxTasks.Store(int64(workers))
	return e
}

// SetIdentity 设置节点身份。worker_id 会带上节点名，队列页能直接看出作业被谁领走。
func (e *TaskExecutor) SetIdentity(nodeID, nodeName string) {
	e.nodeID = nodeID
	e.nodeName = nodeName
}

// SetDispatcher 让执行器改为「只调度、不本地执行」：River Work 把任务推给远程 worker。
func (e *TaskExecutor) SetDispatcher(d NodeDispatcher) {
	e.dispatcher = d
}

// SetLocalFallback 在 all 模式下启用：没有已连接的远程节点时退回本机扫描。
func (e *TaskExecutor) SetLocalFallback(enabled bool) {
	e.localFallback = enabled
}

// NewRemoteTaskExecutor 创建远程 worker 的执行器：任务/结果都走平台 HTTP，
// 不使用 repo / River / 本地任务表。
func NewRemoteTaskExecutor(workers int, remote *RemoteClient) *TaskExecutor {
	if workers <= 0 {
		workers = 5
	}
	if workers > MaxNodeWorkers {
		workers = MaxNodeWorkers
	}
	e := &TaskExecutor{
		taskService:   &remoteTaskStore{client: remote},
		resultService: newRemoteResultStore(remote),
		assets:        remoteAssetStore{client: remote},
		remote:        true,
		workers:       workers,
		stopCh:        make(chan struct{}),
		runningTasks:  make(map[string]*runningTask),
	}
	e.maxTasks.Store(int64(workers))
	return e
}

// Running 返回本进程当前正在执行的任务数。
func (e *TaskExecutor) Running() int {
	return int(atomic.LoadInt64(&e.running))
}

// SetPaused 控制是否接受新作业；已在执行的任务不受影响。
func (e *TaskExecutor) SetPaused(paused bool) {
	e.paused.Store(paused)
}

// SetMaxTasks 在线调低并发上限；超过启动容量的值会被夹回 workers 并返回实际值。
// 调低时正在执行的任务继续完成，新作业由 River Work 返回 snooze 让出。
func (e *TaskExecutor) SetMaxTasks(n int) int {
	if n < 0 {
		n = 0
	}
	if n > e.workers {
		n = e.workers
	}
	e.maxTasks.Store(int64(n))
	return n
}

// acquireSlot 占一个并发槽。CAS 保证多 worker 同时执行时不会超过上限。
func (e *TaskExecutor) acquireSlot() bool {
	for {
		max := e.maxTasks.Load()
		if max <= 0 {
			return false
		}
		cur := atomic.LoadInt64(&e.running)
		if cur >= max {
			return false
		}
		if atomic.CompareAndSwapInt64(&e.running, cur, cur+1) {
			return true
		}
	}
}

func (e *TaskExecutor) releaseSlot() {
	atomic.AddInt64(&e.running, -1)
}

// flushResults 把远程 worker 缓存的结果上传完再结束任务。
func (e *TaskExecutor) flushResults(ctx context.Context, taskID string) error {
	if f, ok := e.resultService.(resultFlusher); ok {
		return f.Flush(ctx, taskID)
	}
	return nil
}

// Start 启动任务状态监控与租约回收。
// 远程 worker 不接 PostgreSQL，只保留状态监控（状态来自平台 HTTP）。
func (e *TaskExecutor) Start() {
	if e.remote {
		e.wg.Add(1)
		go e.taskStatusMonitor()
		log.Printf("[TaskExecutor] 远程 worker 执行器已启动（max_tasks=%d）", e.workers)
		return
	}
	if e.jobs == nil {
		if r := repo.Default(); r != nil {
			e.jobs = r.Jobs()
		}
	}
	if e.jobs == nil {
		log.Println("[TaskExecutor] 数据层未初始化，执行器不会启动")
		return
	}

	// 启动任务状态监控
	e.wg.Add(1)
	go e.taskStatusMonitor()

	// 租约回收只处理通用队列（task_jobs kind='job'）与去重表清理；
	// 扫描作业的租约/重试已交给 River。
	e.wg.Add(1)
	go e.reaper()

	log.Printf("[TaskExecutor] 维护循环已启动（node=%q, river max_workers=%d）", e.nodeName, e.workers)
}

// Stop 停止执行器。
// 先取消正在跑的任务：否则 worker 会一直等扫描上下文（最长 30 分钟），
// 进程收到 SIGTERM 后卡在优雅退出里。
func (e *TaskExecutor) Stop() {
	e.runningMutex.Lock()
	for _, rt := range e.runningTasks {
		if rt.cancelFunc != nil {
			rt.cancelFunc()
		}
	}
	e.runningMutex.Unlock()

	close(e.stopCh)
	e.wg.Wait()
	log.Println("[TaskExecutor] Stopped")
}

// registerRunningTask 注册正在运行的任务
func (e *TaskExecutor) registerRunningTask(taskID string, cancelFunc context.CancelFunc, pipe *pipeline.StreamingPipeline) {
	e.runningMutex.Lock()
	defer e.runningMutex.Unlock()
	e.runningTasks[taskID] = &runningTask{
		cancelFunc: cancelFunc,
		pipeline:   pipe,
	}
}

// unregisterRunningTask 取消注册运行中的任务
func (e *TaskExecutor) unregisterRunningTask(taskID string) {
	e.runningMutex.Lock()
	defer e.runningMutex.Unlock()
	delete(e.runningTasks, taskID)
}

// cancelRunningTask 取消正在运行的任务
func (e *TaskExecutor) cancelRunningTask(taskID string) bool {
	e.runningMutex.RLock()
	rt, exists := e.runningTasks[taskID]
	e.runningMutex.RUnlock()

	if exists && rt != nil {
		log.Printf("[TaskExecutor] Cancelling running task: %s", taskID)
		if rt.pipeline != nil {
			rt.pipeline.Stop()
		}
		if rt.cancelFunc != nil {
			rt.cancelFunc()
		}
		return true
	}
	return false
}

// taskStatusMonitor 监控任务状态，取消被删除或取消的任务
func (e *TaskExecutor) taskStatusMonitor() {
	defer e.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.checkRunningTasks()
		}
	}
}

// checkRunningTasks 检查正在运行的任务状态
func (e *TaskExecutor) checkRunningTasks() {
	e.runningMutex.RLock()
	taskIDs := make([]string, 0, len(e.runningTasks))
	for taskID := range e.runningTasks {
		taskIDs = append(taskIDs, taskID)
	}
	e.runningMutex.RUnlock()

	for _, taskID := range taskIDs {
		task, err := e.taskService.GetTaskByID(taskID)
		if err != nil || task == nil {
			// 任务已被删除，取消执行
			log.Printf("[TaskExecutor] Task %s deleted, cancelling", taskID)
			e.cancelRunningTask(taskID)
			continue
		}

		if task.Status == models.TaskStatusCancelled || task.Status == models.TaskStatusPaused {
			log.Printf("[TaskExecutor] Task %s status changed to %s, cancelling", taskID, task.Status)
			e.cancelRunningTask(taskID)
		}
	}
}

// RunScanJob 是 River 扫描作业的入口。
// 作业的领取、租约、重试由 River 管理；这里只负责把任务状态推进到 running，
// 执行流水线，并根据落库后的任务状态决定 River 作业是完成、取消还是稍后重试。
func (e *TaskExecutor) RunScanJob(ctx context.Context, taskID string, riverJobID int64) error {
	if ctx.Err() != nil {
		// 节点正在退出：把作业立即放回队列，交给其他节点。
		return river.JobSnooze(0)
	}
	if e.dispatcher != nil {
		err := e.runDispatch(ctx, taskID, riverJobID)
		if errors.Is(err, ErrNoNodeAvailable) {
			if e.localFallback {
				return e.runLocalScan(ctx, taskID, riverJobID)
			}
			return river.JobSnooze(3 * time.Second)
		}
		return err
	}
	return e.runLocalScan(ctx, taskID, riverJobID)
}

// runLocalScan 在本进程执行流水线（单机模式，或 all 模式下没有远程节点时的回退）。
func (e *TaskExecutor) runLocalScan(ctx context.Context, taskID string, riverJobID int64) error {
	task, err := e.taskService.GetTaskByID(taskID)
	if err != nil {
		log.Printf("[TaskExecutor] River job %d: task %s is gone: %v", riverJobID, taskID, err)
		return river.JobCancel(fmt.Errorf("任务不存在: %w", err))
	}

	switch task.Status {
	case models.TaskStatusCompleted, models.TaskStatusFailed,
		models.TaskStatusCancelled, models.TaskStatusPaused:
		log.Printf("[TaskExecutor] River job %d dropped: task %s status=%s", riverJobID, taskID, task.Status)
		return nil
	}

	// 节点被管理员停用或并发已满：把作业 snooze 回队列，不占用也不丢失。
	if e.paused.Load() {
		return river.JobSnooze(2 * time.Second)
	}
	if !e.acquireSlot() {
		return river.JobSnooze(2 * time.Second)
	}
	defer e.releaseSlot()

	if task.Status == models.TaskStatusPending {
		updates := map[string]interface{}{
			"status":     models.TaskStatusRunning,
			"started_at": time.Now(),
		}
		if e.nodeID != "" {
			updates["node_id"] = e.nodeID
		}
		if err := e.taskService.UpdateTask(task.ID.Hex(), updates); err != nil {
			return fmt.Errorf("启动任务失败: %w", err)
		}
		task.Status = models.TaskStatusRunning
		task.NodeID = e.nodeID
	} else if e.nodeID != "" && task.NodeID == "" {
		// 续跑的历史任务没有 node_id 时补上，方便在任务列表里定位执行节点。
		_ = e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{"node_id": e.nodeID})
		task.NodeID = e.nodeID
	}

	log.Printf("[%s] Processing task %s (river job %d)", e.nodeName, task.ID.Hex(), riverJobID)
	e.processTask(ctx, task, 0)

	updated, err := e.taskService.GetTaskByID(taskID)
	if err != nil || updated == nil {
		return nil
	}
	switch updated.Status {
	case models.TaskStatusFailed:
		// 任务已落库为失败，避免 River 反复重跑；人工重试会重新入队。
		return river.JobCancel(fmt.Errorf("任务失败: %s", updated.LastError))
	case models.TaskStatusCompleted, models.TaskStatusCancelled, models.TaskStatusPaused:
		return nil
	}

	if ctx.Err() != nil {
		return river.JobSnooze(0)
	}
	return fmt.Errorf("任务未正常结束，状态=%s", updated.Status)
}

// runDispatch 是 master 的 River Work：把任务推给已连接的 worker，并等它完成。
func (e *TaskExecutor) runDispatch(ctx context.Context, taskID string, riverJobID int64) error {
	task, err := e.taskService.GetTaskByID(taskID)
	if err != nil {
		return river.JobCancel(fmt.Errorf("任务不存在: %w", err))
	}
	switch task.Status {
	case models.TaskStatusCompleted, models.TaskStatusFailed,
		models.TaskStatusCancelled, models.TaskStatusPaused:
		return nil
	}

	// 节点不连数据库：任务级字典必须在这里物化成词表随任务下发，
	// 否则节点侧 loadTaskDictionary 会报「数据层未初始化」直接失败。
	if err := e.materializeTaskWordlists(ctx, task); err != nil {
		return river.JobCancel(fmt.Errorf("准备任务词表失败: %w", err))
	}

	if err := e.dispatcher.Dispatch(ctx, taskID); err != nil {
		if errors.Is(err, ErrNoNodeAvailable) {
			return ErrNoNodeAvailable
		}
		return fmt.Errorf("分发任务失败: %w", err)
	}

	updated, err := e.taskService.GetTaskByID(taskID)
	if err != nil || updated == nil {
		return nil
	}
	switch updated.Status {
	case models.TaskStatusFailed:
		return river.JobCancel(fmt.Errorf("任务失败: %s", updated.LastError))
	case models.TaskStatusCompleted, models.TaskStatusCancelled, models.TaskStatusPaused:
		return nil
	}
	if ctx.Err() != nil {
		return river.JobSnooze(0)
	}
	log.Printf("[TaskExecutor] River job %d dispatched task %s finished with status=%s", riverJobID, taskID, updated.Status)
	return nil
}

// materializeTaskWordlists 把任务引用的字典展开成词表，写回任务 config。
// 远端节点没有数据库连接，只能消费随任务下发的词表。
func (e *TaskExecutor) materializeTaskWordlists(ctx context.Context, task *models.Task) error {
	changed, err := materializeTaskConfigDictionaries(ctx, task)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{"config": task.Config})
}

// reaper 回收租约过期的作业：worker 被 kill -9 时由它把作业放回队列，
// 顺带清理过期的 token 黑名单和 7 天前的去重键。
func (e *TaskExecutor) reaper() {
	defer e.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			n, err := e.jobs.Reap(context.Background(), 50)
			if err != nil {
				log.Printf("[TaskExecutor] Reap error: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("[TaskExecutor] Reaped %d expired jobs", n)
			}
		}
	}
}

// finishJob 收尾旧 task_jobs 作业（历史兼容）。River 扫描作业不使用这个路径。
func (e *TaskExecutor) finishJob(jobID int64, errMsg string) {
	if jobID <= 0 || e.jobs == nil {
		return
	}
	ctx := context.Background()
	if errMsg == "" {
		if err := e.jobs.Complete(ctx, jobID, nil); err != nil {
			log.Printf("[TaskExecutor] Complete job %d error: %v", jobID, err)
		}
		return
	}
	status, err := e.jobs.Retry(ctx, jobID, errMsg, 30*time.Second)
	if err != nil {
		log.Printf("[TaskExecutor] Retry job %d error: %v", jobID, err)
		return
	}
	log.Printf("[TaskExecutor] Job %d failed -> %s: %s", jobID, status, errMsg)
}

// processTask 处理任务。ctx 来自 River，节点退出/作业超时时会取消流水线。
func (e *TaskExecutor) processTask(ctx context.Context, task *models.Task, jobID int64) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TaskExecutor] Panic in task %s: %v", task.ID.Hex(), r)
			e.failTask(task, jobID, "内部错误")
		}
	}()

	// 使用 StreamingPipeline 处理所有扫描任务
	switch task.Type {
	case models.TaskTypeFull:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   15,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: true,
			SubdomainHTTPProbe:     true, // 启用 HTTP 探测
			PortScan:               true,
			PortScanMode:           "top1000",
			SkipCDN:                true,
			Fingerprint:            true,
			VulnScan:               true,
			WebCrawler:             true,
			DirScan:                true,
			SensitiveScan:          true,
		})

	case models.TaskTypeSubdomain:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   10,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: false,
			SubdomainHTTPProbe:     true, // 启用 HTTP 探测获取标题、状态码等
			PortScan:               false,
		})

	case models.TaskTypeTakeover:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   10,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: true,
			SubdomainHTTPProbe:     true, // 启用 HTTP 探测
			PortScan:               false,
		})

	case models.TaskTypePortScan:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "top1000",
			SkipCDN:       true,
			Fingerprint:   true,
		})

	case models.TaskTypeFingerprint:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
		})

	case models.TaskTypeVulnScan:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			VulnScan:      true,
		})

	case models.TaskTypeDirScan:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			DirScan:       true,
		})

	case models.TaskTypeCrawler:
		e.executeStreamingPipeline(ctx, task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			WebCrawler:    true,
		})

	case models.TaskTypeServiceID, models.TaskTypeServiceDetect:
		e.executeServiceIdentify(ctx, task, jobID)

	case models.TaskTypeExposure:
		e.executeExposureScan(ctx, task, jobID)

	case models.TaskTypeClueHunt:
		e.executeClueHunt(ctx, task, jobID)

	case models.TaskTypeCustom:
		// 根据用户选择的 scanTypes 构建配置
		config := e.buildCustomConfig(task)
		e.executeStreamingPipeline(ctx, task, jobID, config)

	default:
		e.failTask(task, jobID, "未知的任务类型: "+string(task.Type))
	}
}

// buildCustomConfig 根据用户选择的 scanTypes 构建 PipelineConfig
func (e *TaskExecutor) buildCustomConfig(task *models.Task) *pipeline.PipelineConfig {
	scanTypes := make(map[string]bool)
	for _, t := range task.Config.ScanTypes {
		scanTypes[t] = true
	}

	config := &pipeline.PipelineConfig{
		// 基础配置
		SkipCDN:      true,
		PortScanMode: "top1000",
	}

	// 根据选择的扫描类型启用对应模块
	if scanTypes["subdomain"] {
		config.SubdomainScan = true
		config.SubdomainMaxEnumTime = 15
		config.SubdomainResolveIP = true
		config.SubdomainHTTPProbe = true // 启用 HTTP 探测获取标题、状态码等
	}

	if scanTypes["takeover"] {
		config.SubdomainScan = true // 接管检测需要先扫描子域名
		config.SubdomainCheckTakeover = true
	}

	if scanTypes["port_scan"] {
		config.PortScan = true
	}

	if scanTypes["fingerprint"] || scanTypes["service_detect"] {
		config.PortScan = true // 指纹识别需要先扫描端口
		config.Fingerprint = true
	}

	if scanTypes["crawler"] {
		config.WebCrawler = true
		// 爬虫需要先有 HTTP 服务，确保端口扫描和指纹识别启用
		if !config.PortScan {
			config.PortScan = true
			config.PortScanMode = "quick"
		}
		config.Fingerprint = true
	}

	if scanTypes["dir_scan"] {
		config.DirScan = true
		// 目录扫描需要先有 HTTP 服务
		if !config.PortScan {
			config.PortScan = true
			config.PortScanMode = "quick"
		}
		config.Fingerprint = true
	}

	if scanTypes["vuln_scan"] {
		config.VulnScan = true
		// 漏洞扫描需要先有服务信息
		if !config.PortScan {
			config.PortScan = true
			config.PortScanMode = "quick"
		}
		config.Fingerprint = true
	}

	if scanTypes["sensitive"] {
		config.SensitiveScan = true
	}

	log.Printf("[TaskExecutor] Built custom config for task %s: subdomain=%v, port=%v, fingerprint=%v, crawler=%v, dirscan=%v, vuln=%v, sensitive=%v",
		task.ID.Hex(), config.SubdomainScan, config.PortScan, config.Fingerprint, config.WebCrawler, config.DirScan, config.VulnScan, config.SensitiveScan)

	return config
}

// executeStreamingPipeline 使用 StreamingPipeline 执行任务
// applyScanTypes 用任务配置里的模块列表覆盖流水线模块开关。
// 只描述「扫什么」；模块之间的依赖在这里补齐，模板不用承担链路知识。
func applyScanTypes(cfg *pipeline.PipelineConfig, scanTypes []string) {
	if len(scanTypes) == 0 {
		return
	}

	cfg.SubdomainScan = false
	cfg.PortScan = false
	cfg.Fingerprint = false
	cfg.VulnScan = false
	cfg.WebCrawler = false
	cfg.DirScan = false
	cfg.SensitiveScan = false

	for _, raw := range scanTypes {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "subdomain":
			cfg.SubdomainScan = true
		case "port_scan", "portscan", "port":
			cfg.PortScan = true
		case "fingerprint":
			cfg.Fingerprint = true
		case "vuln_scan", "vulnscan", "vuln":
			cfg.VulnScan = true
		case "crawler":
			cfg.WebCrawler = true
		case "dir_scan", "dirscan", "directory":
			cfg.DirScan = true
		case "sensitive":
			cfg.SensitiveScan = true
		}
	}

	if cfg.SubdomainScan {
		if cfg.SubdomainMaxEnumTime <= 0 {
			cfg.SubdomainMaxEnumTime = 10
		}
		cfg.SubdomainResolveIP = true
		cfg.SubdomainHTTPProbe = true
	}

	// 依赖补齐：指纹/爬虫/目录/敏感都要吃 HTTP 端点，漏洞要吃指纹结果。
	// 少了上游模块整条链就断了，所以这里自动带上。
	if cfg.Fingerprint || cfg.WebCrawler || cfg.DirScan || cfg.SensitiveScan || cfg.VulnScan {
		cfg.PortScan = true
	}
	if cfg.VulnScan || cfg.WebCrawler || cfg.DirScan || cfg.SensitiveScan {
		cfg.Fingerprint = true
	}
	if cfg.PortScan {
		if cfg.PortScanMode == "" {
			cfg.PortScanMode = "quick"
		}
		cfg.SkipCDN = true
	}
}

func (e *TaskExecutor) executeStreamingPipeline(parent context.Context, task *models.Task, jobID int64, config *pipeline.PipelineConfig) {
	ctx, cancel := context.WithTimeout(parent, 24*time.Hour)
	taskID := task.ID.Hex()

	// 任务级节奏控制：调用方给的模块配置只决定「扫什么」，
	// 「扫多快」统一由任务配置决定，避免各类型任务里散落硬编码速率。
	if task.Config.RatePerSec > 0 {
		config.RatePerSec = task.Config.RatePerSec
	}
	if task.Config.TargetDelayMs > 0 {
		config.TargetDelayMs = task.Config.TargetDelayMs
	}

	// 模块组合：任务配置里显式勾选 scan_types 时以其为准，
	// 让「信息收集（不含漏洞）」「全量扫描」这类模板能自由组合模块，
	// 而不是被任务类型对应的硬编码开关锁死。
	applyScanTypes(config, task.Config.ScanTypes)

	log.Printf("[TaskExecutor] Starting StreamingPipeline for task %s, type: %s, rate=%d/s delay=%dms",
		taskID, task.Type, config.Rate(), config.TargetDelayMs)

	// 任务级字典：master 派单前已把条目物化进 config；节点侧直接用，
	// 只有 master 本地执行（没物化）时才回落到数据库读取。
	if config.SubdomainScan && len(config.SubdomainWordlist) == 0 {
		if len(task.Config.SubdomainWordlist) > 0 {
			config.SubdomainWordlist = task.Config.SubdomainWordlist
			log.Printf("[TaskExecutor] 使用随任务下发的子域词表 %d 条", len(task.Config.SubdomainWordlist))
		} else if strings.TrimSpace(task.Config.SubdomainDictID) != "" {
			values, derr := loadTaskDictionary(ctx, task.Config.SubdomainDictID, "subdomain", 5000)
			if derr != nil {
				cancel()
				e.failTask(task, jobID, "加载子域字典失败: "+derr.Error())
				return
			}
			config.SubdomainWordlist = values
			log.Printf("[TaskExecutor] 使用任务字典 %s，子域词表 %d 条", task.Config.SubdomainDictID, len(values))
		}
	}
	if config.DirScan && len(config.DirWordlist) == 0 {
		values := task.Config.DirWordlist
		if len(values) == 0 && strings.TrimSpace(task.Config.DirDictID) != "" {
			loaded, derr := loadTaskDictionary(ctx, task.Config.DirDictID, "directory", 20000)
			if derr != nil {
				cancel()
				e.failTask(task, jobID, "加载目录字典失败: "+derr.Error())
				return
			}
			values = loaded
		}
		if len(values) > 0 {
			path, werr := writeTempWordlist(values)
			if werr != nil {
				cancel()
				e.failTask(task, jobID, "写入目录字典失败: "+werr.Error())
				return
			}
			defer os.Remove(path)
			config.DirWordlist = []string{path}
			log.Printf("[TaskExecutor] 目录词表 %d 条已写入临时文件", len(values))
		}
	}

	// 资产入库范围由任务勾选的扫描类型决定（任务配置可显式覆盖）。
	ingestPorts := task.Config.WantsPorts(task.Type)
	ingestURLs := task.Config.WantsURLs(task.Type)
	ingestFingerprints := task.Config.WantsFingerprints(task.Type)
	ingestIcons := task.Config.WantsIcons(task.Type)
	log.Printf("[TaskExecutor] 资产入库: ports=%v urls=%v fingerprints=%v icons=%v",
		ingestPorts, ingestURLs, ingestFingerprints, ingestIcons)

	// 创建带进度追踪的流水线
	progressCallback := func(report *pipeline.ProgressReport) {
		// 更新任务进度到数据库
		e.updateProgressWithDetails(task, report)
	}

	scanPipe := pipeline.NewStreamingPipelineWithProgress(ctx, task, config, len(task.Targets), progressCallback)

	// 注册正在运行的任务
	e.registerRunningTask(taskID, cancel, scanPipe)
	defer func() {
		e.unregisterRunningTask(taskID)
		cancel()
	}()

	// 启动流水线
	if err := scanPipe.Start(task.Targets); err != nil {
		e.failTask(task, jobID, fmt.Sprintf("流水线启动失败: %v", err))
		return
	}

	// CDN 信息映射 (domain -> CDN provider)
	cdnInfo := make(map[string]string)

	// 收集结果
	var resultCount int
	var subdomainCount, portCount, vulnCount, urlCount int
	var takeoverCount int

	// 路由采集：子域/URL 结果里的地址按 host 归到站点，循环结束后统一落库。
	crawledRoutes := make([]CrawledEndpoint, 0, 256)
	// 资产归并：任务的扫描结果按 project_id 自动并入 sites/raw_records。
	assetRecords := make([]repo.RawRecord, 0, 256)
	taskScope := scope.New(task.Targets)

	// 发现即落库：每攒够一小批就写入，不再等整个任务结束。
	// 失败时保留切片，下一批继续重试，避免结果被清空。
	flushAssets := func(force bool) {
		if len(assetRecords) == 0 && len(crawledRoutes) == 0 {
			return
		}
		if !force && len(assetRecords) < 20 && len(crawledRoutes) < 50 {
			return
		}
		if len(assetRecords) > 0 {
			if err := e.assets.Ingest(ctx, task, assetRecords); err != nil {
				log.Printf("[TaskExecutor] 扫描结果增量并入资产失败: %v", err)
			} else {
				assetRecords = assetRecords[:0]
			}
		}
		if len(crawledRoutes) > 0 {
			if err := e.assets.SaveRoutes(ctx, task, crawledRoutes); err != nil {
				log.Printf("[TaskExecutor] 增量保存路由失败: %v", err)
			} else {
				crawledRoutes = crawledRoutes[:0]
			}
		}
	}

	// 进度更新计时器
	progressTicker := time.NewTicker(3 * time.Second)
	defer progressTicker.Stop()

	for result := range scanPipe.Results() {
		// 检查上下文是否被取消
		select {
		case <-ctx.Done():
			log.Printf("[TaskExecutor] Task %s cancelled during result collection", taskID)
			e.finishJob(jobID, "")
			return
		default:
		}

		resultCount++

		// 根据结果类型保存到数据库
		var scanResult *models.ScanResult
		switch r := result.(type) {
		case pipeline.SubdomainResult:
			subdomainCount++
			if r.URL != "" && taskScope.AllowsURL(r.URL) {
				crawledRoutes = append(crawledRoutes, CrawledEndpoint{URL: r.URL, Method: "GET", StatusCode: r.StatusCode})
			}
			if rec, ok := rawRecordFromScan(r.URL, r.Host, "https", r.StatusCode, r.Title, firstIP(r.IPs), r.Technologies); ok && taskScope.AllowsHost(rec.Host) {
				rec.Server = r.WebServer
				if !ingestFingerprints {
					rec.Tech = nil
				}
				assetRecords = append(assetRecords, rec)
			}
			// 更新进度追踪器
			if tracker := scanPipe.GetProgressTracker(); tracker != nil {
				tracker.IncrementModuleOutput("SubdomainScan", 1)
			}
			scanResult = subdomainScanResult(task, r)

		case pipeline.DomainSkip:
			// 记录 CDN 信息，稍后更新子域名结果
			if r.IsCDN && r.CDN != "" {
				cdnInfo[r.Domain] = r.CDN
			}
			// DomainSkip 不需要单独存储，它的信息会合并到子域名结果中

		case pipeline.PortAlive:
			if r.Port != "" {
				portCount++
				scanResult = &models.ScanResult{
					TaskID:      task.ID,
					WorkspaceID: task.WorkspaceID,
					Type:        models.ResultTypePort,
					Source:      "gogo",
					Data: map[string]interface{}{
						"host":    r.Host,
						"ip":      r.IP,
						"port":    r.Port,
						"service": r.Service,
					},
					CreatedAt: time.Now(),
				}
				// 端口结果同时并入资产域：站点仍是 host 粒度，端口写 site_endpoints。
				if ingestPorts {
					if port, perr := strconv.Atoi(strings.TrimSpace(r.Port)); perr == nil {
						if rec, ok := rawRecordFromPort(r.Host, port, r.Service, r.IP); ok && taskScope.AllowsHost(rec.Host) {
							assetRecords = append(assetRecords, rec)
						}
					}
				}
			}

		case pipeline.AssetHttp:
			if rec, ok := rawRecordFromScan(r.URL, r.Host, "https", r.StatusCode, r.Title, r.IP, r.Technologies); ok && taskScope.AllowsHost(rec.Host) {
				rec.Server = r.Server
				if ingestFingerprints {
					rec.Tech = r.Technologies
				} else {
					rec.Tech = nil
				}
				if ingestIcons {
					rec.IconSHA256 = r.IconSHA256
					rec.IconMMH3 = r.IconMMH3
					rec.IconContentType = r.IconContentType
					rec.IconData = r.IconData
				}
				assetRecords = append(assetRecords, rec)
			}
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeService,
				Source:      "fingerprint",
				Data: map[string]interface{}{
					"url":          r.URL,
					"host":         r.Host,
					"ip":           r.IP,
					"port":         r.Port,
					"title":        r.Title,
					"status_code":  r.StatusCode,
					"server":       r.Server,
					"technologies": r.Technologies,
					"fingerprints": r.Fingerprints,
				},
				CreatedAt: time.Now(),
			}

		case pipeline.VulnResult:
			vulnCount++
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeVuln,
				Source:      r.Source,
				Data: map[string]interface{}{
					"vuln_id":     r.VulnID,
					"name":        r.Name,
					"target":      r.Target,
					"severity":    r.Severity,
					"description": r.Description,
					"evidence":    r.Evidence,
					"remediation": r.Remediation,
					"reference":   r.Reference,
					"matched_at":  r.MatchedAt,
				},
				CreatedAt: time.Now(),
			}

		case pipeline.UrlResult:
			if !taskScope.AllowsURL(r.Output) {
				continue
			}
			urlCount++
			crawledRoutes = append(crawledRoutes, CrawledEndpoint{
				URL: r.Output, Method: r.Method, StatusCode: r.StatusCode,
			})
			// 爬虫/目录扫描发现的 URL 也进资产：站点仍按 host 归并，路径作为原始记录。
			if ingestURLs {
				if rec, ok := rawRecordFromScan(r.Output, "", "https", r.StatusCode, "", "", nil); ok && taskScope.AllowsHost(rec.Host) {
					assetRecords = append(assetRecords, rec)
				}
			}
			// 根据 Source 区分结果类型
			var resultType models.ResultType
			switch r.Source {
			case "dirscan":
				resultType = models.ResultTypeDirScan
			case "katana", "rad":
				resultType = models.ResultTypeCrawler
			default:
				resultType = models.ResultTypeURL
			}
			// 规范化 URL（移除默认端口）
			normalizedURL := normalizeURL(r.Output)
			normalizedInput := normalizeURL(r.Input)
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        resultType,
				Source:      r.Source,
				Data: map[string]interface{}{
					"url":          normalizedURL,
					"input":        normalizedInput,
					"target":       normalizedInput, // 同时存储 target 字段供前端显示
					"method":       r.Method,
					"source":       r.Source,
					"crawler":      r.Source, // 爬虫来源
					"status_code":  r.StatusCode,
					"status":       r.StatusCode, // 兼容前端
					"content_type": r.ContentType,
					"length":       r.Length,
					"size":         r.Length, // 兼容前端
				},
				CreatedAt: time.Now(),
			}

		case pipeline.SensitiveInfoResult:
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSensitive,
				Source:      r.Source,
				Data: map[string]interface{}{
					"target":     r.Target,
					"url":        r.URL,
					"type":       r.Type,
					"pattern":    r.Pattern,
					"matches":    r.Matches,
					"location":   r.Location,
					"severity":   r.Severity,
					"confidence": r.Confidence,
				},
				CreatedAt: time.Now(),
			}

		case pipeline.TakeoverResult:
			// 接管检测结果：只处理 vulnerable。安全的域名不落结果——
			// 接管检测的语义是"发现可接管"，不是"全部扫过"，
			// 全量落库会让结果表被无信息量的条目占满。
			if !r.Vulnerable {
				continue
			}
			takeoverCount++
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeTakeover,
				Source:      "takeover_scanner",
				Data: map[string]interface{}{
					"subdomain":    r.Domain,
					"cname":        r.CNAME,
					"provider":     r.Service,
					"vulnerable":   true,
					"fingerprints": r.Fingerprints,
					"reason":       r.Reason,
					"severity":     "high",
				},
				CreatedAt: time.Now(),
			}
			// 接管资产写一条变更事件，并沉淀为待复核漏洞：
			// 变更时间线要能回答"什么时候发现它能被接管"，
			// 漏洞域要能让复核流处理这个结论。
			IngestTakeover(ctx, task, r)
		}

		// 保存结果
		if scanResult != nil {
			var err error
			// 扫描期就去重：同一任务内重复发现的同类结果只保留最新一条，
			// 既避免结果表膨胀，也减少任务完成后的归并压力。
			switch scanResult.Type {
			case models.ResultTypeSubdomain, models.ResultTypeService, models.ResultTypeURL, models.ResultTypeCrawler, models.ResultTypeDirScan:
				err = e.resultService.CreateResultWithDedup(scanResult)
			default:
				err = e.resultService.CreateResult(scanResult)
			}
			if err != nil {
				log.Printf("[TaskExecutor] Failed to save result: %v", err)
			}
		}

		// 资产/路由发现到一小批就落库，任务列表和资产页不用等全量结束。
		flushAssets(false)

		// 定期更新进度（基于结果数量，进度追踪器会更精确地计算）
		if resultCount%50 == 0 {
			if tracker := scanPipe.GetProgressTracker(); tracker != nil {
				report := tracker.GetReport()
				e.updateProgressWithDetails(task, report)
			}
		}
	}

	// 扫描结束：把最后不足一批的资产/路由补写。
	flushAssets(true)

	// 批量更新子域名的 CDN 信息
	if len(cdnInfo) > 0 {
		log.Printf("[TaskExecutor] Updating CDN info for %d subdomains", len(cdnInfo))
		for domain, cdnProvider := range cdnInfo {
			if err := e.resultService.UpdateSubdomainCDN(task.ID.Hex(), domain, cdnProvider); err != nil {
				log.Printf("[TaskExecutor] Failed to update CDN info for %s: %v", domain, err)
			}
		}
	}

	// 检查任务是否被取消或删除
	currentTask, err := e.taskService.GetTaskByID(taskID)
	if err != nil || currentTask == nil {
		log.Printf("[TaskExecutor] Task %s was deleted during execution", taskID)
		e.finishJob(jobID, "")
		return
	}
	if currentTask.Status == models.TaskStatusCancelled {
		log.Printf("[TaskExecutor] Task %s was cancelled during execution", taskID)
		e.finishJob(jobID, "")
		return
	}
	// 节点退出或作业超时：不能把半截扫描标成 completed，留给 River 重新调度。
	if ctx.Err() != nil {
		log.Printf("[TaskExecutor] Task %s interrupted (%v), leaving status=%s", taskID, ctx.Err(), currentTask.Status)
		e.finishJob(jobID, "")
		return
	}

	// 任务完成：结果计数一并写回，任务列表/巡航依赖这几个字段做统计。
	// discovered_assets 的口径 = 子域 + 端口 + URL（漏洞单独计）。
	if e.taskService != nil {
		_ = e.taskService.UpdateTask(taskID, map[string]interface{}{
			"discovered_assets": subdomainCount + portCount + urlCount,
			"discovered_ports":  portCount,
			"discovered_vulns":  vulnCount,
		})
	}
	log.Printf("[TaskExecutor] Task %s completed: subdomains=%d, ports=%d, vulns=%d, urls=%d, takeovers=%d",
		taskID, subdomainCount, portCount, vulnCount, urlCount, takeoverCount)
	if err := e.flushResults(ctx, taskID); err != nil {
		e.failTask(task, jobID, "扫描结果上传失败: "+err.Error())
		return
	}
	e.completeTask(task, jobID, resultCount)
}

// updateProgress 更新任务进度（简单版本）
func (e *TaskExecutor) updateProgress(task *models.Task, progress int) {
	// 执行器的纯扫描逻辑允许被单测直接调用（没有 taskService 时不落库）
	if e.taskService == nil {
		return
	}
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"progress": progress,
	})
}

// updateProgressWithDetails 更新任务进度（详细版本）
func (e *TaskExecutor) updateProgressWithDetails(task *models.Task, report *pipeline.ProgressReport) {
	if report == nil {
		return
	}

	// 构建进度详情
	progressDetails := map[string]interface{}{
		"current_module":      report.CurrentModule,
		"elapsed_time":        report.ElapsedTime,
		"estimated_time_left": report.EstimatedTimeLeft,
		"total_results":       report.TotalResults,
	}

	// 模块进度
	moduleProgress := make(map[string]interface{})
	for name, mp := range report.ModuleProgresses {
		moduleProgress[name] = map[string]interface{}{
			"status":    mp.Status,
			"progress":  mp.Progress,
			"total":     mp.TotalItems,
			"processed": mp.ProcessedItems,
			"output":    mp.OutputItems,
		}
	}
	progressDetails["modules"] = moduleProgress

	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"progress":         report.OverallProgress,
		"progress_details": progressDetails,
	})
}

// saveResults 保存扫描结果
func (e *TaskExecutor) saveResults(task *models.Task, results []models.ScanResult) {
	for i := range results {
		r := &results[i]
		r.TaskID = task.ID
		r.WorkspaceID = task.WorkspaceID
		if err := e.resultService.CreateResult(r); err != nil {
			log.Printf("[TaskExecutor] Failed to save result: %v", err)
		}
	}
}

// completeTask 完成任务
func (e *TaskExecutor) completeTask(task *models.Task, jobID int64, resultCount int) {
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusCompleted,
		"progress":     100,
		"completed_at": time.Now(),
		"result_count": resultCount,
	})
	log.Printf("[TaskExecutor] Task %s completed with %d results", task.ID.Hex(), resultCount)
	e.finishJob(jobID, "")

	// 远程 worker 只负责执行，通知由平台在派单完成时统一发。
	if e.remote {
		return
	}
	// 发送通知
	summary := fmt.Sprintf("扫描任务已完成\n目标: %v\n结果数量: %d", task.Targets, resultCount)
	stats := map[string]interface{}{
		"result_count": resultCount,
		"targets":      task.Targets,
		"type":         task.Type,
	}
	notify.GetGlobalManager().NotifyTaskComplete(task.Name, task.ID.Hex(), true, summary, stats)
}

// failTask 任务失败
func (e *TaskExecutor) failTask(task *models.Task, jobID int64, errMsg string) {
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusFailed,
		"completed_at": time.Now(),
		"last_error":   errMsg,
	})
	log.Printf("[TaskExecutor] Task %s failed: %s", task.ID.Hex(), errMsg)
	e.finishJob(jobID, errMsg)

	if e.remote {
		return
	}
	// 发送通知
	summary := fmt.Sprintf("扫描任务失败\n目标: %v\n错误: %s", task.Targets, errMsg)
	stats := map[string]interface{}{
		"error":   errMsg,
		"targets": task.Targets,
		"type":    task.Type,
	}
	notify.GetGlobalManager().NotifyTaskComplete(task.Name, task.ID.Hex(), false, summary, stats)
}

// executorIsIPAddress 判断是否为 IP 地址 (executor专用)
func executorIsIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// normalizeURL 规范化 URL（移除默认端口）
func normalizeURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	// 移除 :443 (HTTPS 默认端口)
	if len(rawURL) > 4 {
		// https://example.com:443/path -> https://example.com/path
		rawURL = strings.Replace(rawURL, ":443/", "/", 1)
		// https://example.com:443 -> https://example.com
		if strings.HasSuffix(rawURL, ":443") {
			rawURL = rawURL[:len(rawURL)-4]
		}
	}

	// 移除 :80 (HTTP 默认端口)
	if len(rawURL) > 3 {
		// http://example.com:80/path -> http://example.com/path
		rawURL = strings.Replace(rawURL, ":80/", "/", 1)
		// http://example.com:80 -> http://example.com
		if strings.HasSuffix(rawURL, ":80") {
			rawURL = rawURL[:len(rawURL)-3]
		}
	}

	return rawURL
}

// subdomainScanResult 把流水线子域结果映射成结果行。
// 原始发现和 HTTP 探测后的增强回写共用同一份结构，去重键都是 subdomain。
func subdomainScanResult(task *models.Task, r pipeline.SubdomainResult) *models.ScanResult {
	return &models.ScanResult{
		TaskID:      task.ID,
		WorkspaceID: task.WorkspaceID,
		Type:        models.ResultTypeSubdomain,
		Source:      r.Source,
		Data: map[string]interface{}{
			"subdomain":    r.Host,
			"domain":       r.Domain,
			"root_domain":  r.RootDomain,
			"ips":          r.IPs,
			"cnames":       r.CNAMEs,
			"title":        r.Title,
			"status_code":  r.StatusCode,
			"web_server":   r.WebServer,
			"technologies": r.Technologies,
			"cdn":          r.CDN,
			"cdn_name":     r.CDNName,
			"url":          r.URL,
			"alive":        r.StatusCode > 0,
		},
		CreatedAt: time.Now(),
	}
}

// rawRecordFromScan 把一条扫描结果转成资产原始记录。
// URL 优先；没有 URL 但已有主机时按协议拼一个。status=0 且无 URL 的纯 DNS 记录不入资产。
func rawRecordFromScan(rawURL, host, defaultProto string, status int, title, ip string, tech []string) (repo.RawRecord, bool) {
	rawURL = strings.TrimSpace(rawURL)
	host = strings.TrimSpace(host)
	if rawURL == "" {
		if host == "" || status == 0 {
			return repo.RawRecord{}, false
		}
		proto := defaultProto
		if proto == "" {
			proto = "https"
		}
		rawURL = proto + "://" + host
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return repo.RawRecord{}, false
	}
	h := u.Hostname()
	proto := u.Scheme
	if proto == "" {
		proto = defaultProto
	}
	if proto == "" {
		proto = "https"
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}

	evidence := map[string]any{}
	if len(tech) > 0 {
		evidence["tech"] = tech
	}
	return repo.RawRecord{
		Source:     "scan",
		Host:       h,
		Port:       port,
		Protocol:   proto,
		Value:      rawURL,
		StatusCode: status,
		Title:      title,
		IP:         ip,
		Tech:       tech,
		Evidence:   evidence,
	}, true
}

// rawRecordFromPort 把开放端口转成资产原始记录。
// HTTP/HTTPS 之外的服务用服务名做 scheme（ssh/ftp/...），无法识别时记 tcp；
// 站点仍按 host 归并，这些端口最终进 site_endpoints。
func rawRecordFromPort(host string, port int, service, ip string) (repo.RawRecord, bool) {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || port > 65535 {
		return repo.RawRecord{}, false
	}
	svc := strings.ToLower(strings.TrimSpace(service))
	// site_endpoints 的 scheme 只收 http/https/tcp；具体服务名留在 evidence。
	proto := "tcp"
	switch {
	case strings.Contains(svc, "https"):
		proto = "https"
	case strings.Contains(svc, "http"):
		proto = "http"
	case svc != "" && svc != "unknown":
		proto = "tcp"
	case port == 443 || port == 8443:
		proto = "https"
	case port == 80 || port == 8080 || port == 8000 || port == 8008 || port == 3000 || port == 5000:
		proto = "http"
	}
	evidence := map[string]any{}
	if svc != "" {
		evidence["service"] = svc
	}
	return repo.RawRecord{
		Source:   "scan",
		Host:     host,
		Port:     port,
		Protocol: proto,
		Value:    net.JoinHostPort(host, strconv.Itoa(port)),
		IP:       strings.TrimSpace(ip),
		Evidence: evidence,
	}, true
}

func firstIP(ips []string) string {
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}
