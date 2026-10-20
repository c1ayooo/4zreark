package service

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
	"github.com/c1ayooo/4zreark/service/pipeline"

	"go.mongodb.org/mongo-driver/bson"
)

// runningTask 正在运行的任务信息
type runningTask struct {
	cancelFunc context.CancelFunc
	pipeline   *pipeline.StreamingPipeline
}

// TaskExecutor 任务执行器
type TaskExecutor struct {
	taskService   *TaskService
	resultService *ResultService
	jobs          repo.JobRepo
	workers       int
	lease         time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup
	// 正在运行的任务，用于取消
	runningTasks map[string]*runningTask
	runningMutex sync.RWMutex
}

// NewTaskExecutor 创建任务执行器
func NewTaskExecutor(workers int) *TaskExecutor {
	if workers <= 0 {
		workers = 5
	}
	return &TaskExecutor{
		taskService:   NewTaskService(),
		resultService: NewResultService(),
		workers:       workers,
		lease:         5 * time.Minute,
		stopCh:        make(chan struct{}),
		runningTasks:  make(map[string]*runningTask),
	}
}

// Start 启动执行器
func (e *TaskExecutor) Start() {
	if e.jobs == nil {
		if r := repo.Default(); r != nil {
			e.jobs = r.Jobs()
		}
	}
	if e.jobs == nil {
		log.Println("[TaskExecutor] 数据层未初始化，执行器不会启动")
		return
	}

	// 每个 worker 领取任意类型的扫描作业，类型分派在 processTask 里做
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	// 启动任务状态监控
	e.wg.Add(1)
	go e.taskStatusMonitor()

	// 启动租约回收：进程崩溃后遗留的 running 作业由它放回队列
	e.wg.Add(1)
	go e.reaper()

	log.Printf("[TaskExecutor] Started %d workers (postgres backed, lease %s)", e.workers, e.lease)
}

// Stop 停止执行器
func (e *TaskExecutor) Stop() {
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

// worker 工作者循环：从 task_jobs 领取作业（SKIP LOCKED），执行完按结果收尾。
func (e *TaskExecutor) worker(id int) {
	defer e.wg.Done()
	workerID := fmt.Sprintf("worker-%d", id)
	log.Printf("[%s] Worker started", workerID)

	backoff := 200 * time.Millisecond
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		job, err := e.jobs.ClaimScan(context.Background(), workerID, e.lease)
		if err != nil {
			log.Printf("[%s] Claim error: %v", workerID, err)
			time.Sleep(1 * time.Second)
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

		task, err := e.taskService.GetTaskByID(job.TaskID)
		if err != nil {
			log.Printf("[%s] Task %s is gone, dropping job %d", workerID, job.TaskID, job.ID)
			e.finishJob(job.ID, "")
			continue
		}

		switch task.Status {
		case models.TaskStatusCancelled, models.TaskStatusPaused,
			models.TaskStatusCompleted, models.TaskStatusFailed:
			// 排队期间任务状态已经变了，这条作业没有执行的意义
			log.Printf("[%s] Task %s status=%s, dropping job %d", workerID, task.ID.Hex(), task.Status, job.ID)
			e.finishJob(job.ID, "")
			continue
		case models.TaskStatusPending:
			if err := e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
				"status":     models.TaskStatusRunning,
				"started_at": time.Now(),
			}); err != nil {
				log.Printf("[%s] Failed to start task %s: %v", workerID, task.ID.Hex(), err)
				e.finishJob(job.ID, "启动任务失败: "+err.Error())
				continue
			}
			task.Status = models.TaskStatusRunning
		}

		log.Printf("[%s] Processing task: %s (job %d)", workerID, task.ID.Hex(), job.ID)
		e.processTask(task, job.ID)
	}
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

// heartbeat 在任务执行期间续租，避免长任务被 reaper 当成崩溃回收。
func (e *TaskExecutor) heartbeat(jobID int64, stop <-chan struct{}) {
	interval := e.lease / 3
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := e.jobs.Renew(context.Background(), jobID, e.lease); err != nil {
				log.Printf("[TaskExecutor] Renew job %d error: %v", jobID, err)
			}
		}
	}
}

// finishJob 收尾作业：errMsg 为空算完成，否则走重试策略（超次数标 dead）。
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

// processTask 处理任务
func (e *TaskExecutor) processTask(task *models.Task, jobID int64) {
	if jobID > 0 {
		stopHeartbeat := make(chan struct{})
		go e.heartbeat(jobID, stopHeartbeat)
		defer close(stopHeartbeat)
	}

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TaskExecutor] Panic in task %s: %v", task.ID.Hex(), r)
			e.failTask(task, jobID, "内部错误")
		}
	}()

	// 使用 StreamingPipeline 处理所有扫描任务
	switch task.Type {
	case models.TaskTypeFull:
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
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
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   10,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: false,
			SubdomainHTTPProbe:     true, // 启用 HTTP 探测获取标题、状态码等
			PortScan:               false,
		})

	case models.TaskTypeTakeover:
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   10,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: true,
			SubdomainHTTPProbe:     true, // 启用 HTTP 探测
			PortScan:               false,
		})

	case models.TaskTypePortScan:
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "top1000",
			SkipCDN:       true,
			Fingerprint:   true,
		})

	case models.TaskTypeFingerprint:
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
		})

	case models.TaskTypeVulnScan:
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			VulnScan:      true,
		})

	case models.TaskTypeDirScan:
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			DirScan:       true,
		})

	case models.TaskTypeCrawler:
		e.executeStreamingPipeline(task, jobID, &pipeline.PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			WebCrawler:    true,
		})

	case models.TaskTypeCustom:
		// 根据用户选择的 scanTypes 构建配置
		config := e.buildCustomConfig(task)
		e.executeStreamingPipeline(task, jobID, config)

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
func (e *TaskExecutor) executeStreamingPipeline(task *models.Task, jobID int64, config *pipeline.PipelineConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	taskID := task.ID.Hex()

	log.Printf("[TaskExecutor] Starting StreamingPipeline for task %s, type: %s", taskID, task.Type)

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
			// 更新进度追踪器
			if tracker := scanPipe.GetProgressTracker(); tracker != nil {
				tracker.IncrementModuleOutput("SubdomainScan", 1)
			}
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSubdomain,
				Source:      r.Source,
				Data: bson.M{
					"subdomain":    r.Host,   // 子域名完整名称
					"domain":       r.Domain, // 根域名
					"root_domain":  r.RootDomain,
					"ips":          r.IPs,
					"cnames":       r.CNAMEs,
					"title":        r.Title,        // 页面标题
					"status_code":  r.StatusCode,   // HTTP 状态码
					"web_server":   r.WebServer,    // Web 服务器
					"technologies": r.Technologies, // 技术栈/指纹
					"cdn":          r.CDN,          // 是否为 CDN
					"cdn_name":     r.CDNName,      // CDN 名称
					"url":          r.URL,          // 完整 URL
					"alive":        r.StatusCode > 0,
				},
				CreatedAt: time.Now(),
			}

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
					Data: bson.M{
						"host":    r.Host,
						"ip":      r.IP,
						"port":    r.Port,
						"service": r.Service,
					},
					CreatedAt: time.Now(),
				}
			}

		case pipeline.AssetHttp:
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeService,
				Source:      "fingerprint",
				Data: bson.M{
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
				Data: bson.M{
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
			urlCount++
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
				Data: bson.M{
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
				Data: bson.M{
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
		}

		// 保存结果
		if scanResult != nil {
			var err error
			// 对于需要去重的类型，使用 CreateResultWithDedup
			switch scanResult.Type {
			case models.ResultTypeService, models.ResultTypeURL, models.ResultTypeCrawler, models.ResultTypeDirScan:
				err = e.resultService.CreateResultWithDedup(scanResult)
			default:
				err = e.resultService.CreateResult(scanResult)
			}
			if err != nil {
				log.Printf("[TaskExecutor] Failed to save result: %v", err)
			}
		}

		// 定期更新进度（基于结果数量，进度追踪器会更精确地计算）
		if resultCount%50 == 0 {
			if tracker := scanPipe.GetProgressTracker(); tracker != nil {
				report := tracker.GetReport()
				e.updateProgressWithDetails(task, report)
			}
		}
	}

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

	// 任务完成
	log.Printf("[TaskExecutor] Task %s completed: subdomains=%d, ports=%d, vulns=%d, urls=%d",
		taskID, subdomainCount, portCount, vulnCount, urlCount)
	e.completeTask(task, jobID, resultCount)
}

// updateProgress 更新任务进度（简单版本）
func (e *TaskExecutor) updateProgress(task *models.Task, progress int) {
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
	resultService := NewResultService()
	for _, result := range results {
		if err := resultService.CreateResult(&result); err != nil {
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
		"error":        errMsg,
	})
	log.Printf("[TaskExecutor] Task %s failed: %s", task.ID.Hex(), errMsg)
	e.finishJob(jobID, errMsg)

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
