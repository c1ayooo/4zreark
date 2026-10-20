package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/robfig/cron/v3"
)

// 调度器与 entryMap 必须是进程级的。
// handler 每次 NewCruiseService() 都会拿到新实例，如果 cron 挂在实例上，
// HTTP 触发的「启用」只会加到一个从没 Start 过的调度器里，表现为
// 「状态变成 enabled，但永远不会执行」。
var (
	sharedCron     *cron.Cron
	sharedCronOnce sync.Once

	cruiseEntries  = make(map[string]cron.EntryID)
	cruiseEntryMu  sync.RWMutex
	cruiseRunning  bool
	cruiseRunState sync.Mutex
)

func cronScheduler() *cron.Cron {
	sharedCronOnce.Do(func() {
		sharedCron = cron.New(cron.WithLocation(time.Local))
	})
	return sharedCron
}

// CruiseService 巡航任务服务：调度用 cron，数据全在 PG。
type CruiseService struct {
	taskService *TaskService
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewCruiseService 创建巡航服务
func NewCruiseService() *CruiseService {
	ctx, cancel := context.WithCancel(context.Background())
	return &CruiseService{
		taskService: NewTaskService(),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (s *CruiseService) store() (repo.CruiseRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, fmt.Errorf("数据库未就绪")
	}
	return r.Cruises(), nil
}

// Start 启动巡航调度器
func (s *CruiseService) Start() error {
	log.Println("[CruiseService] Starting cruise scheduler...")

	cruiseRunState.Lock()
	if cruiseRunning {
		cruiseRunState.Unlock()
		return nil
	}
	// 先启动调度器再加条目：cron 只在 Start 之后才会算出 Entry.Next，
	// 反过来做的话启动时加载的巡航拿到的下次执行时间是零值。
	cronScheduler().Start()
	cruiseRunning = true
	cruiseRunState.Unlock()

	log.Println("[CruiseService] Cruise scheduler started")

	if err := s.loadEnabledCruises(); err != nil {
		log.Printf("[CruiseService] Failed to load cruises: %v", err)
		return err
	}
	return nil
}

// Stop 停止巡航调度器
func (s *CruiseService) Stop() {
	log.Println("[CruiseService] Stopping cruise scheduler...")
	s.cancel()

	cruiseRunState.Lock()
	if cruiseRunning {
		ctx := cronScheduler().Stop()
		<-ctx.Done()
		cruiseRunning = false
	}
	cruiseRunState.Unlock()

	log.Println("[CruiseService] Cruise scheduler stopped")
}

// loadEnabledCruises 加载所有启用的巡航任务
func (s *CruiseService) loadEnabledCruises() error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	cruises, err := store.ListEnabled(ctx)
	if err != nil {
		return err
	}

	log.Printf("[CruiseService] Loading %d enabled cruise tasks", len(cruises))
	for _, cruise := range cruises {
		if err := s.scheduleCruise(cruise); err != nil {
			log.Printf("[CruiseService] Failed to schedule cruise %s: %v", cruise.ID.Hex(), err)
		}
	}
	return nil
}

// scheduleCruise 调度单个巡航任务
func (s *CruiseService) scheduleCruise(cruise *models.CruiseTask) error {
	cruiseID := cruise.ID.Hex()

	cruiseEntryMu.Lock()
	if entryID, exists := cruiseEntries[cruiseID]; exists {
		cronScheduler().Remove(entryID)
		delete(cruiseEntries, cruiseID)
	}

	entryID, err := cronScheduler().AddFunc(cruise.CronExpr, func() {
		s.executeCruise(cruise.ID)
	})
	if err != nil {
		cruiseEntryMu.Unlock()
		return fmt.Errorf("invalid cron expression: %v", err)
	}
	cruiseEntries[cruiseID] = entryID
	next := cronScheduler().Entry(entryID).Next
	cruiseEntryMu.Unlock()

	// 写库放在锁外：这里会走一次数据库往返
	s.updateNextRunTime(cruise.ID, next)

	log.Printf("[CruiseService] Scheduled cruise %s with cron: %s, next run: %v",
		cruise.Name, cruise.CronExpr, next)
	return nil
}

// unscheduleCruise 取消调度
func (s *CruiseService) unscheduleCruise(cruiseID string) {
	cruiseEntryMu.Lock()
	defer cruiseEntryMu.Unlock()

	if entryID, exists := cruiseEntries[cruiseID]; exists {
		cronScheduler().Remove(entryID)
		delete(cruiseEntries, cruiseID)
		log.Printf("[CruiseService] Unscheduled cruise %s", cruiseID)
	}
}

// executeCruise 执行巡航任务
func (s *CruiseService) executeCruise(cruiseID oid.ObjectID) {
	hexID := cruiseID.Hex()
	log.Printf("[CruiseService] Executing cruise: %s", hexID)

	cruise, err := s.GetCruise(hexID)
	if err != nil {
		log.Printf("[CruiseService] Failed to get cruise %s: %v", hexID, err)
		return
	}
	if cruise.Status != models.CruiseStatusEnabled {
		log.Printf("[CruiseService] Cruise %s is not enabled, skipping", cruise.Name)
		return
	}

	s.updateCruiseStatus(cruiseID, models.CruiseStatusRunning)
	startTime := time.Now()

	task := &models.Task{
		WorkspaceID: cruise.WorkspaceID,
		Name:        fmt.Sprintf("[巡航] %s - %s", cruise.Name, startTime.Format("2006-01-02 15:04")),
		Description: fmt.Sprintf("自动巡航任务，来源: %s", cruise.Name),
		Type:        cruise.TaskType,
		Status:      models.TaskStatusPending,
		Targets:     cruise.Targets,
		TargetType:  cruise.TargetType,
		Config:      cruise.Config,
		IsScheduled: true,
		CreatedBy:   cruise.CreatedBy,
		Tags:        append(cruise.Tags, "cruise", "auto"),
		CreatedAt:   startTime,
		UpdatedAt:   startTime,
	}

	if err := s.taskService.CreateTask(task); err != nil {
		log.Printf("[CruiseService] Failed to create task for cruise %s: %v", cruise.Name, err)
		s.recordCruiseLog(cruiseID, oid.NilObjectID, "failed", startTime, time.Now(), 0, 0, err.Error())
		s.updateCruiseStatus(cruiseID, models.CruiseStatusEnabled)
		s.incrementFailCount(cruiseID)
		return
	}

	taskID := task.ID.Hex()
	taskObjID := task.ID

	s.recordCruiseLog(cruiseID, taskObjID, "running", startTime, time.Time{}, 0, 0, "")
	s.updateLastRun(cruiseID, taskID, startTime)

	// 任务已通过 CreateTask 入队，这里只跟踪它的最终状态。
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		timeout := time.After(24 * time.Hour)

		for {
			select {
			case <-ticker.C:
				updatedTask, err := s.taskService.GetTaskByID(taskID)
				if err != nil {
					continue
				}
				if updatedTask.Status != models.TaskStatusCompleted &&
					updatedTask.Status != models.TaskStatusFailed &&
					updatedTask.Status != models.TaskStatusCancelled {
					continue
				}

				endTime := time.Now()
				duration := int64(endTime.Sub(startTime).Seconds())
				resultCount := updatedTask.ResultStats.DiscoveredAssets
				vulnCount := updatedTask.ResultStats.DiscoveredVulns
				status := "success"
				errorMsg := ""

				switch updatedTask.Status {
				case models.TaskStatusFailed:
					status = "failed"
					errorMsg = updatedTask.LastError
				case models.TaskStatusCancelled:
					status = "cancelled"
				}

				s.updateCruiseLog(cruiseID, taskObjID, status, endTime, duration, resultCount, vulnCount, errorMsg)
				s.updateCruiseStatus(cruiseID, models.CruiseStatusEnabled)
				s.updateLastStatus(cruiseID, status)

				if status == "success" {
					s.incrementSuccessCount(cruiseID)
				} else {
					s.incrementFailCount(cruiseID)
				}

				cruiseEntryMu.RLock()
				entryID, exists := cruiseEntries[hexID]
				var next time.Time
				if exists {
					next = cronScheduler().Entry(entryID).Next
				}
				cruiseEntryMu.RUnlock()
				if exists {
					s.updateNextRunTime(cruiseID, next)
				}

				log.Printf("[CruiseService] Cruise %s completed, status: %s, results: %d, vulns: %d",
					cruise.Name, status, resultCount, vulnCount)
				return

			case <-timeout:
				log.Printf("[CruiseService] Cruise %s task timeout", cruise.Name)
				s.updateCruiseLog(cruiseID, taskObjID, "timeout", time.Now(),
					int64(24*time.Hour.Seconds()), 0, 0, "任务执行超时")
				s.updateCruiseStatus(cruiseID, models.CruiseStatusEnabled)
				s.incrementFailCount(cruiseID)
				return
			}
		}
	}()
}

// CreateCruise 创建巡航任务
func (s *CruiseService) CreateCruise(req *models.CruiseTaskCreateRequest, userID, workspaceID oid.ObjectID) (*models.CruiseTask, error) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if _, err := parser.Parse(req.CronExpr); err != nil {
		return nil, fmt.Errorf("invalid cron expression: %v", err)
	}

	now := time.Now()
	timezone := req.Timezone
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}

	cruise := &models.CruiseTask{
		ID:               oid.NewObjectID(),
		WorkspaceID:      workspaceID,
		Name:             req.Name,
		Description:      req.Description,
		Status:           models.CruiseStatusDisabled, // 默认禁用，需手动启用
		CronExpr:         req.CronExpr,
		Timezone:         timezone,
		Targets:          req.Targets,
		TargetType:       req.TargetType,
		TaskType:         req.TaskType,
		Config:           req.Config,
		NotifyOnComplete: req.NotifyOnComplete,
		NotifyOnVuln:     req.NotifyOnVuln,
		NotifyChannels:   req.NotifyChannels,
		Tags:             req.Tags,
		CreatedBy:        userID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.Create(ctx, cruise); err != nil {
		return nil, err
	}

	log.Printf("[CruiseService] Created cruise task: %s (ID: %s)", cruise.Name, cruise.ID.Hex())
	return cruise, nil
}

// UpdateCruise 更新巡航任务
func (s *CruiseService) UpdateCruise(cruiseID string, req *models.CruiseTaskUpdateRequest) error {
	update := map[string]interface{}{}

	if req.Name != nil {
		update["name"] = *req.Name
	}
	if req.Description != nil {
		update["description"] = *req.Description
	}
	if req.CronExpr != nil {
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if _, err := parser.Parse(*req.CronExpr); err != nil {
			return fmt.Errorf("invalid cron expression: %v", err)
		}
		update["cron_expr"] = *req.CronExpr
	}
	if req.Timezone != nil {
		update["timezone"] = *req.Timezone
	}
	if req.Targets != nil {
		update["targets"] = req.Targets
	}
	if req.TargetType != nil {
		update["target_type"] = *req.TargetType
	}
	if req.TaskType != nil {
		update["task_type"] = string(*req.TaskType)
	}
	if req.Config != nil {
		update["config"] = *req.Config
	}
	if req.NotifyOnComplete != nil {
		update["notify_on_complete"] = *req.NotifyOnComplete
	}
	if req.NotifyOnVuln != nil {
		update["notify_on_vuln"] = *req.NotifyOnVuln
	}
	if req.NotifyChannels != nil {
		update["notify_channels"] = req.NotifyChannels
	}
	if req.Tags != nil {
		update["tags"] = req.Tags
	}

	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.UpdateFields(ctx, cruiseID, update); err != nil {
		return err
	}

	// cron 变了且任务是启用状态，重新调度
	if req.CronExpr != nil {
		cruise, getErr := s.GetCruise(cruiseID)
		if getErr == nil && cruise.Status == models.CruiseStatusEnabled {
			s.scheduleCruise(cruise)
		}
	}
	return nil
}

// DeleteCruise 删除巡航任务（连同执行日志）
func (s *CruiseService) DeleteCruise(cruiseID string) error {
	s.unscheduleCruise(cruiseID)

	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.Delete(ctx, cruiseID); err != nil {
		return err
	}
	log.Printf("[CruiseService] Deleted cruise task: %s", cruiseID)
	return nil
}

// GetCruise 获取单个巡航任务
func (s *CruiseService) GetCruise(cruiseID string) (*models.CruiseTask, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	cruise, err := store.Get(ctx, cruiseID)
	if err != nil {
		return nil, err
	}
	return cruise, nil
}

// ListCruises 列出巡航任务
func (s *CruiseService) ListCruises(workspaceID oid.ObjectID, page, pageSize int, search string) ([]models.CruiseTask, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ws := ""
	if !workspaceID.IsZero() {
		ws = workspaceID.Hex()
	}

	cruises, total, err := store.List(ctx, ws, page, pageSize, search)
	if err != nil {
		return nil, 0, err
	}

	out := make([]models.CruiseTask, 0, len(cruises))
	for _, c := range cruises {
		out = append(out, *c)
	}
	log.Printf("[CruiseService] ListCruises found %d cruises (total: %d)", len(out), total)
	return out, total, nil
}

// EnableCruise 启用巡航任务
func (s *CruiseService) EnableCruise(cruiseID string) error {
	cruise, err := s.GetCruise(cruiseID)
	if err != nil {
		return err
	}
	if cruise.Status == models.CruiseStatusEnabled {
		return nil
	}
	if err := s.scheduleCruise(cruise); err != nil {
		return err
	}
	return s.updateCruiseStatus(cruise.ID, models.CruiseStatusEnabled)
}

// DisableCruise 禁用巡航任务
func (s *CruiseService) DisableCruise(cruiseID string) error {
	objID, err := oid.ObjectIDFromHex(cruiseID)
	if err != nil {
		return err
	}
	s.unscheduleCruise(cruiseID)
	return s.updateCruiseStatus(objID, models.CruiseStatusDisabled)
}

// RunNow 立即执行一次
func (s *CruiseService) RunNow(cruiseID string) error {
	objID, err := oid.ObjectIDFromHex(cruiseID)
	if err != nil {
		return err
	}
	go s.executeCruise(objID)
	return nil
}

// GetCruiseLogs 获取巡航执行日志
func (s *CruiseService) GetCruiseLogs(cruiseID string, page, pageSize int) ([]models.CruiseLog, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logs, total, err := store.ListLogs(ctx, cruiseID, page, pageSize)
	if err != nil {
		return nil, 0, err
	}

	out := make([]models.CruiseLog, 0, len(logs))
	for _, l := range logs {
		out = append(out, *l)
	}
	return out, total, nil
}

// GetStats 获取巡航统计
func (s *CruiseService) GetStats(workspaceID oid.ObjectID) map[string]interface{} {
	store, err := s.store()
	if err != nil {
		return map[string]interface{}{"total": 0, "enabled": 0, "disabled": 0, "running": 0}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ws := ""
	if !workspaceID.IsZero() {
		ws = workspaceID.Hex()
	}
	total, enabled, running, err := store.Stats(ctx, ws)
	if err != nil {
		log.Printf("[CruiseService] GetStats failed: %v", err)
	}
	return map[string]interface{}{
		"total":    total,
		"enabled":  enabled,
		"disabled": total - enabled - running,
		"running":  running,
	}
}

// ---------------------------------------------------------------- 内部写入

func (s *CruiseService) updateCruiseStatus(cruiseID oid.ObjectID, status models.CruiseStatus) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.SetStatus(ctx, cruiseID.Hex(), string(status))
}

func (s *CruiseService) updateNextRunTime(cruiseID oid.ObjectID, nextRun time.Time) {
	if nextRun.IsZero() {
		return
	}
	store, err := s.store()
	if err != nil {
		return
	}
	ctx, cancel := dbCtx()
	defer cancel()
	if err := store.SetNextRun(ctx, cruiseID.Hex(), nextRun); err != nil {
		log.Printf("[CruiseService] Failed to update next run: %v", err)
	}
}

func (s *CruiseService) updateLastRun(cruiseID oid.ObjectID, taskID string, lastRun time.Time) {
	store, err := s.store()
	if err != nil {
		return
	}
	ctx, cancel := dbCtx()
	defer cancel()
	if err := store.MarkRun(ctx, cruiseID.Hex(), taskID, lastRun); err != nil {
		log.Printf("[CruiseService] Failed to mark run: %v", err)
	}
}

func (s *CruiseService) updateLastStatus(cruiseID oid.ObjectID, status string) {
	store, err := s.store()
	if err != nil {
		return
	}
	ctx, cancel := dbCtx()
	defer cancel()
	_ = store.SetLastStatus(ctx, cruiseID.Hex(), status)
}

func (s *CruiseService) incrementSuccessCount(cruiseID oid.ObjectID) {
	store, err := s.store()
	if err != nil {
		return
	}
	ctx, cancel := dbCtx()
	defer cancel()
	_ = store.IncrSuccess(ctx, cruiseID.Hex())
}

func (s *CruiseService) incrementFailCount(cruiseID oid.ObjectID) {
	store, err := s.store()
	if err != nil {
		return
	}
	ctx, cancel := dbCtx()
	defer cancel()
	_ = store.IncrFail(ctx, cruiseID.Hex())
}

func (s *CruiseService) recordCruiseLog(cruiseID, taskID oid.ObjectID, status string,
	startTime, endTime time.Time, resultCount, vulnCount int, errMsg string) {

	store, err := s.store()
	if err != nil {
		return
	}
	ctx, cancel := dbCtx()
	defer cancel()

	var duration int64
	if !endTime.IsZero() {
		duration = int64(endTime.Sub(startTime).Seconds())
	}

	entry := &models.CruiseLog{
		CruiseID:    cruiseID,
		TaskID:      taskID,
		Status:      status,
		StartTime:   startTime,
		EndTime:     endTime,
		Duration:    duration,
		ResultCount: resultCount,
		VulnCount:   vulnCount,
		Error:       errMsg,
		CreatedAt:   time.Now(),
	}
	if id, err := store.AddLog(ctx, entry); err == nil {
		entry.ID = id
	} else {
		log.Printf("[CruiseService] Failed to write cruise log: %v", err)
	}
}

func (s *CruiseService) updateCruiseLog(cruiseID, taskID oid.ObjectID, status string,
	endTime time.Time, duration int64, resultCount, vulnCount int, errMsg string) {

	store, err := s.store()
	if err != nil {
		return
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.FinishLog(ctx, cruiseID.Hex(), taskID.Hex(), status, endTime,
		duration, resultCount, vulnCount, errMsg); err != nil {
		log.Printf("[CruiseService] Failed to finish cruise log: %v", err)
	}
}
