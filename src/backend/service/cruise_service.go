package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/robfig/cron/v3"
	"golang.org/x/net/publicsuffix"
)

// 单次巡航最多派生的目标数：项目资产可能上万，任务列表和扫描队列都吃不消。
const maxCruiseTargets = 5000

// TargetPreview 是项目资产派生结果的预览。
type TargetPreview struct {
	TargetType string   `json:"target_type"`
	Targets    []string `json:"targets"`
	Total      int      `json:"total"`
	Truncated  bool     `json:"truncated"`
}

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

	// 进程刚启动不可能有在跑的巡航：把上次崩溃残留在 running 的记录复位，
	// 否则这些巡航不在 ListEnabled 里，调度和「立即执行」都被永久拒绝。
	if store, err := s.store(); err == nil {
		ctx, cancel := dbCtx()
		if n, rerr := store.ResetStaleRunning(ctx); rerr != nil {
			log.Printf("[CruiseService] Failed to reset stale running cruises: %v", rerr)
		} else if n > 0 {
			log.Printf("[CruiseService] Reset %d stale running cruise(s) from previous run", n)
		}
		cancel()
	}

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

	spec, err := cruiseScheduleSpec(cruise.CronExpr, cruise.Timezone)
	if err != nil {
		return err
	}

	cruiseEntryMu.Lock()
	if entryID, exists := cruiseEntries[cruiseID]; exists {
		cronScheduler().Remove(entryID)
		delete(cruiseEntries, cruiseID)
	}

	entryID, err := cronScheduler().AddFunc(spec, func() {
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
	s.executeCruiseWithMode(cruiseID, false)
}

// executeCruiseWithMode 执行巡航。manual=true 时允许对已禁用任务「立即执行」，
// 执行结束后恢复原来的启用状态，不会把禁用任务顺带启用。
func (s *CruiseService) executeCruiseWithMode(cruiseID oid.ObjectID, manual bool) {
	hexID := cruiseID.Hex()
	log.Printf("[CruiseService] Executing cruise: %s (manual=%v)", hexID, manual)

	cruise, err := s.GetCruise(hexID)
	if err != nil {
		log.Printf("[CruiseService] Failed to get cruise %s: %v", hexID, err)
		return
	}
	if !manual && cruise.Status != models.CruiseStatusEnabled {
		log.Printf("[CruiseService] Cruise %s is not enabled, skipping", cruise.Name)
		return
	}
	if cruise.Status == models.CruiseStatusRunning {
		log.Printf("[CruiseService] Cruise %s is already running, skipping", cruise.Name)
		return
	}

	restoreStatus := models.CruiseStatusEnabled
	if cruise.Status == models.CruiseStatusDisabled {
		restoreStatus = models.CruiseStatusDisabled
	}

	// 原子抢占：cron 触发与「立即执行」并发时只允许一个把状态改成 running，
	// 抢不到的说明另一个入口已经在跑。
	acquired, err := s.acquireCruiseRun(cruiseID)
	if err != nil {
		log.Printf("[CruiseService] Failed to acquire cruise %s: %v", hexID, err)
		return
	}
	if !acquired {
		log.Printf("[CruiseService] Cruise %s is already running (acquired by concurrent trigger), skipping", cruise.Name)
		return
	}
	startTime := time.Now()

	if cruise.ProjectID <= 0 {
		s.failBeforeCreate(cruiseID, cruise.Name, startTime, restoreStatus, errors.New("巡航任务未绑定归属项目"))
		return
	}

	targets := cruise.Targets
	sourceDesc := "固定目标"
	if cruise.TargetSource == models.CruiseTargetSourceProject {
		preview, err := s.PreviewProjectTargets(cruise.ProjectID, cruise.TargetType)
		if err != nil {
			s.failBeforeCreate(cruiseID, cruise.Name, startTime, restoreStatus, err)
			return
		}
		if len(preview.Targets) == 0 {
			s.failBeforeCreate(cruiseID, cruise.Name, startTime, restoreStatus,
				fmt.Errorf("项目暂无 %s 类型的可监控资产", cruise.TargetType))
			return
		}
		targets = preview.Targets
		sourceDesc = fmt.Sprintf("项目 #%d 整体资产派生（%d 个目标", cruise.ProjectID, preview.Total)
		if preview.Truncated {
			sourceDesc += fmt.Sprintf("，已截断到 %d", len(preview.Targets))
		}
		sourceDesc += "）"
	}
	if len(targets) == 0 {
		s.failBeforeCreate(cruiseID, cruise.Name, startTime, restoreStatus, errors.New("巡航目标为空"))
		return
	}

	task := &models.Task{
		ProjectID:   cruise.ProjectID,
		WorkspaceID: cruise.WorkspaceID,
		Name:        fmt.Sprintf("[巡航] %s - %s", cruise.Name, startTime.Format("2006-01-02 15:04")),
		Description: fmt.Sprintf("自动巡航任务，来源: %s（%s）", cruise.Name, sourceDesc),
		Type:        cruise.TaskType,
		Status:      models.TaskStatusPending,
		Targets:     targets,
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
		s.updateCruiseStatus(cruiseID, restoreStatus)
		s.updateLastStatus(cruiseID, "failed")
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
				s.updateCruiseStatus(cruiseID, restoreStatus)
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
				s.updateCruiseStatus(cruiseID, restoreStatus)
				s.incrementFailCount(cruiseID)
				return
			}
		}
	}()
}

// cruiseScheduleSpec 把巡航的 cron 表达式与其 timezone 组装成 robfig/cron 认识的
// spec：时区有效且非 Local 时加 "CRON_TZ=<tz> " 前缀，Entry.Next 与触发时间都按
// 该时区计算。此前 timezone 存而不用，容器默认 UTC 时按北京时间配的 9 点实际 17 点触发。
func cruiseScheduleSpec(cronExpr, timezone string) (string, error) {
	tz := strings.TrimSpace(timezone)
	if tz == "" || tz == "Local" || tz == time.Local.String() {
		return cronExpr, nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return "", fmt.Errorf("无效时区 %q: %v", tz, err)
	}
	_ = loc
	return "CRON_TZ=" + tz + " " + cronExpr, nil
}

// validateCruiseTimezone 校验时区名（空值视为服务器本地时区）。
func validateCruiseTimezone(tz string) error {
	tz = strings.TrimSpace(tz)
	if tz == "" || tz == "Local" {
		return nil
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("无效时区 %q: %v", tz, err)
	}
	return nil
}

// CreateCruise 创建巡航任务
func (s *CruiseService) CreateCruise(req *models.CruiseTaskCreateRequest, userID, workspaceID oid.ObjectID) (*models.CruiseTask, error) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if _, err := parser.Parse(req.CronExpr); err != nil {
		return nil, fmt.Errorf("invalid cron expression: %v", err)
	}
	if err := validateCruiseTimezone(req.Timezone); err != nil {
		return nil, err
	}

	source, err := normalizeCruiseTargetSource(req.TargetSource)
	if err != nil {
		return nil, err
	}
	targetType := normalizeCruiseTargetType(req.TargetType)
	if !validCruiseTargetType(targetType) {
		return nil, fmt.Errorf("不支持的目标类型: %s", targetType)
	}
	if req.ProjectID <= 0 {
		return nil, errors.New("必须选择归属项目（project_id）")
	}

	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := ensureProjectExists(ctx, req.ProjectID); err != nil {
		return nil, err
	}
	targets := cleanCruiseTargets(req.Targets)
	if source == models.CruiseTargetSourceStatic && len(targets) == 0 {
		return nil, errors.New("固定目标模式至少需要一个扫描目标")
	}

	now := time.Now()
	timezone := req.Timezone
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}

	cruise := &models.CruiseTask{
		ID:               oid.NewObjectID(),
		WorkspaceID:      workspaceID,
		ProjectID:        req.ProjectID,
		TargetSource:     source,
		Name:             req.Name,
		Description:      req.Description,
		Status:           models.CruiseStatusDisabled, // 默认禁用，需手动启用
		CronExpr:         req.CronExpr,
		Timezone:         timezone,
		Targets:          targets,
		TargetType:       targetType,
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

	if err := store.Create(ctx, cruise); err != nil {
		return nil, err
	}

	log.Printf("[CruiseService] Created cruise task: %s (ID: %s, project: %d, source: %s)",
		cruise.Name, cruise.ID.Hex(), cruise.ProjectID, cruise.TargetSource)
	return cruise, nil
}

// UpdateCruise 更新巡航任务
func (s *CruiseService) UpdateCruise(cruiseID string, req *models.CruiseTaskUpdateRequest) error {
	current, err := s.GetCruise(cruiseID)
	if err != nil {
		return err
	}

	update := map[string]interface{}{}

	if req.Name != nil {
		update["name"] = *req.Name
	}
	if req.Description != nil {
		update["description"] = *req.Description
	}
	if req.ProjectID != nil {
		if *req.ProjectID <= 0 {
			return errors.New("必须选择归属项目（project_id）")
		}
		update["project_id"] = *req.ProjectID
	}
	if req.TargetSource != nil {
		source, err := normalizeCruiseTargetSource(*req.TargetSource)
		if err != nil {
			return err
		}
		update["target_source"] = source
	}
	if req.CronExpr != nil {
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if _, err := parser.Parse(*req.CronExpr); err != nil {
			return fmt.Errorf("invalid cron expression: %v", err)
		}
		update["cron_expr"] = *req.CronExpr
	}
	if req.Timezone != nil {
		if err := validateCruiseTimezone(*req.Timezone); err != nil {
			return err
		}
		update["timezone"] = *req.Timezone
	}
	if req.Targets != nil {
		update["targets"] = cleanCruiseTargets(req.Targets)
	}
	if req.TargetType != nil {
		tt := normalizeCruiseTargetType(*req.TargetType)
		if !validCruiseTargetType(tt) {
			return fmt.Errorf("不支持的目标类型: %s", tt)
		}
		update["target_type"] = tt
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

	// 用「更新后」的完整状态做校验，避免只改来源或只改目标时漏掉组合约束。
	projectID := current.ProjectID
	if req.ProjectID != nil {
		projectID = *req.ProjectID
	}
	if projectID <= 0 {
		return errors.New("必须选择归属项目（project_id）")
	}
	source := current.TargetSource
	if source == "" {
		source = models.CruiseTargetSourceStatic
	}
	if req.TargetSource != nil {
		source, _ = normalizeCruiseTargetSource(*req.TargetSource)
	}
	targets := current.Targets
	if req.Targets != nil {
		targets = cleanCruiseTargets(req.Targets)
	}
	if source == models.CruiseTargetSourceStatic && len(targets) == 0 {
		return errors.New("固定目标模式至少需要一个扫描目标")
	}
	if req.TargetType != nil && !validCruiseTargetType(normalizeCruiseTargetType(*req.TargetType)) {
		return fmt.Errorf("不支持的目标类型: %s", *req.TargetType)
	}

	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if req.ProjectID != nil {
		if err := ensureProjectExists(ctx, projectID); err != nil {
			return err
		}
	}
	if err := store.UpdateFields(ctx, cruiseID, update); err != nil {
		return err
	}

	// cron / 目标来源变了且任务是启用状态，重新调度。
	if req.CronExpr != nil || req.TargetSource != nil || req.TargetType != nil || req.Targets != nil || req.ProjectID != nil {
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
	if cruise.ProjectID <= 0 {
		return errors.New("请先编辑巡航任务并选择归属项目")
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

// RunNow 立即执行一次（禁用的任务也可以手动执行，结束后恢复禁用状态）
func (s *CruiseService) RunNow(cruiseID string) error {
	objID, err := oid.ObjectIDFromHex(cruiseID)
	if err != nil {
		return err
	}
	cruise, err := s.GetCruise(cruiseID)
	if err != nil {
		return err
	}
	if cruise.ProjectID <= 0 {
		return errors.New("请先编辑巡航任务并选择归属项目")
	}
	if cruise.Status == models.CruiseStatusRunning {
		return errors.New("巡航任务正在执行中")
	}
	go s.executeCruiseWithMode(objID, true)
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

// PreviewProjectTargets 按目标类型预览「项目整体资产」会派生出的监控目标。
func (s *CruiseService) PreviewProjectTargets(projectID int64, targetType string) (*TargetPreview, error) {
	if projectID <= 0 {
		return nil, errors.New("必须选择归属项目（project_id）")
	}
	tt := normalizeCruiseTargetType(targetType)
	if !validCruiseTargetType(tt) {
		return nil, fmt.Errorf("不支持的目标类型: %s", targetType)
	}

	// 资产表可能很大，派生比普通 CRUD 慢，单独放宽超时。
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if err := ensureProjectExists(ctx, projectID); err != nil {
		return nil, err
	}
	values, err := repo.NewAssetRepo().ProjectTargetValues(ctx, projectID, tt)
	if err != nil {
		return nil, err
	}

	var targets []string
	switch tt {
	case "domain":
		targets = projectRootDomains(values)
	case "ip":
		for _, ip := range values {
			if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
				targets = append(targets, parsed.String())
			}
		}
		targets = uniqueSorted(targets)
	case "url":
		for _, raw := range values {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			targets = append(targets, u.String())
		}
		targets = uniqueSorted(targets)
	case "cidr":
		for _, raw := range values {
			_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			targets = append(targets, network.String())
		}
		targets = uniqueSorted(targets)
	}

	total := len(targets)
	truncated := total > maxCruiseTargets
	if truncated {
		targets = targets[:maxCruiseTargets]
	}
	return &TargetPreview{
		TargetType: tt,
		Targets:    targets,
		Total:      total,
		Truncated:  truncated,
	}, nil
}

func normalizeCruiseTargetSource(source string) (string, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		return models.CruiseTargetSourceStatic, nil
	}
	switch source {
	case models.CruiseTargetSourceStatic, models.CruiseTargetSourceProject:
		return source, nil
	default:
		return "", fmt.Errorf("不支持的目标来源: %s", source)
	}
}

func normalizeCruiseTargetType(targetType string) string {
	targetType = strings.ToLower(strings.TrimSpace(targetType))
	if targetType == "" {
		return "domain"
	}
	return targetType
}

func validCruiseTargetType(targetType string) bool {
	switch targetType {
	case "domain", "ip", "url", "cidr":
		return true
	default:
		return false
	}
}

func cleanCruiseTargets(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// projectRootDomains 把站点主机归并成根域，避免对每个子域各跑一遍全量扫描。
func projectRootDomains(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		h := normalizeHostName(raw)
		if h == "" || net.ParseIP(h) != nil || !strings.Contains(h, ".") {
			continue
		}
		if root, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
			h = root
		}
		out = append(out, strings.ToLower(h))
	}
	return uniqueSorted(out)
}

func normalizeHostName(raw string) string {
	h := strings.TrimSpace(strings.ToLower(raw))
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil {
			h = u.Hostname()
		}
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	h = strings.TrimPrefix(h, "*.")
	return strings.TrimSuffix(h, ".")
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func ensureProjectExists(ctx context.Context, projectID int64) error {
	p, err := repo.NewAssetRepo().GetProject(ctx, projectID)
	if errors.Is(err, repo.ErrNotFound) {
		return fmt.Errorf("归属项目 %d 不存在", projectID)
	}
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("归属项目 %d 不存在", projectID)
	}
	return nil
}

func (s *CruiseService) failBeforeCreate(cruiseID oid.ObjectID, name string, startTime time.Time,
	restoreStatus models.CruiseStatus, cause error) {
	log.Printf("[CruiseService] Failed to prepare task for cruise %s: %v", name, cause)
	s.recordCruiseLog(cruiseID, oid.NilObjectID, "failed", startTime, time.Now(), 0, 0, cause.Error())
	s.updateCruiseStatus(cruiseID, restoreStatus)
	s.updateLastStatus(cruiseID, "failed")
	s.incrementFailCount(cruiseID)
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

func (s *CruiseService) acquireCruiseRun(cruiseID oid.ObjectID) (bool, error) {
	store, err := s.store()
	if err != nil {
		return false, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.AcquireRun(ctx, cruiseID.Hex())
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
