package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/oid"
)

// TaskService 负责任务的增删改查、状态流转与入队。
// 数据全部走 repo，本文件不出现任何 SQL 或驱动调用。
type TaskService struct{}

// taskCancelNotifier 由 main 注入 NodeHub.CancelTask；worker 不在本进程时自然 no-op。
// 放在包级别是为了让 TaskService（暂停/取消）和 StaleTaskReaper 都能通知远端节点。
var taskCancelNotifier func(taskID string)

func SetTaskCancelNotifier(fn func(taskID string)) {
	taskCancelNotifier = fn
}

// NotifyTaskCancel 通知正在执行该任务的 worker 取消扫描 context。
func NotifyTaskCancel(taskID string) {
	if taskCancelNotifier != nil {
		taskCancelNotifier(taskID)
	}
}

func NewTaskService() *TaskService {
	return &TaskService{}
}

func (s *TaskService) stores() (repo.TaskRepo, repo.JobRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, nil, errors.New("数据层未初始化")
	}
	return r.Tasks(), r.Jobs(), nil
}

// jobPayload 是扫描作业的载荷：worker 靠它知道该跑哪种流水线。
func jobPayload(taskType models.TaskType) map[string]any {
	return map[string]any{"type": string(taskType)}
}

// CreateTask creates a new task.
//
// 归属规则：一个任务必须属于且只属于一个项目；项目可以有多个任务。
// project_id 是扫描结果自动并入资产域（sites/raw_records）的依据，不能为空。
func (s *TaskService) CreateTask(task *models.Task) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, jobs, err := s.stores()
	if err != nil {
		return err
	}

	if task.ProjectID <= 0 {
		return errors.New("必须选择归属项目（project_id）")
	}
	if r := repo.Default(); r != nil {
		if _, err := repo.NewAssetRepo().GetProject(ctx, task.ProjectID); err != nil {
			return errors.New("归属项目不存在")
		}
	}

	// 字典必须在创建时物化：worker 节点不连数据库，只消费随任务下发的词表。
	if _, err := materializeTaskConfigDictionaries(ctx, task); err != nil {
		return errors.New("准备任务字典失败: " + err.Error())
	}

	// 节点选择：显式指定 > 默认节点 > 空（任意在线节点）。
	if task.NodeID = NewNodeSelectionService().ResolveTaskNode(ctx, task.NodeID); task.NodeID != "" {
		node, err := NewNodeService().GetNodeByID(task.NodeID)
		if err != nil {
			return errors.New("指定的扫描节点不存在")
		}
		if err := CheckNodeUsable(node); err != nil {
			return errors.New("指定的扫描节点不可用: " + err.Error())
		}
	}

	// 引擎查询额度收紧：按当日各引擎余额压低单任务查询上限（只收紧不放宽）。
	// 流水线默认每引擎 10 次；余额不足 10 的按余额走，余额耗尽压到 1
	//（0 会被流水线当成「用默认」处理，压不下去，属已知取舍）。
	if budget := GetEngineBudgetService(); budget.CanAccount() {
		engines := task.Config.ThirdPartySources
		if len(engines) == 0 {
			engines = []string{"fofa", "hunter", "quake", "zoomeye", "shodan"}
		}
		cap := 10
		for _, raw := range engines {
			e := strings.ToLower(strings.TrimSpace(raw))
			remaining, tracked := budget.RemainingToday(ctx, e)
			if tracked && remaining >= 0 && remaining < cap {
				cap = remaining
			}
		}
		if cap < 10 {
			if cap < 1 {
				cap = 1
			}
			task.Config.EngineQueryMaxPerEngine = cap
		}
	}

	if task.ID.IsZero() {
		task.ID = oid.NewObjectID()
	}
	task.Status = models.TaskStatusPending
	task.Progress = 0
	now := time.Now()
	task.CreatedAt = now
	task.UpdatedAt = now

	if err := tasks.Create(ctx, task); err != nil {
		return errors.New("创建任务失败: " + err.Error())
	}

	if err := s.enqueueScan(ctx, task, jobs); err != nil {
		// 任务已落库但没有作业，worker 不会执行它；这属于必须让调用方知道的状态
		log.Printf("[TaskService] 任务 %s 入队失败: %v", task.ID.Hex(), err)
		return errors.New("任务创建成功但入队失败: " + err.Error())
	}

	log.Printf("[TaskService] 任务 %s 已创建并入队", task.ID.Hex())
	// 动作日志：任务创建（功能分类 = 任务类型）
	if err := tasks.AddLogCategory(ctx, task.ID.Hex(), string(task.Type), "info",
		fmt.Sprintf("任务已创建：%d 个目标", len(task.Targets)), ""); err != nil {
		log.Printf("[TaskService] 任务日志写入失败: %v", err)
	}
	return nil
}

// GetTaskByID retrieves task by ID
func (s *TaskService) GetTaskByID(taskID string) (*models.Task, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return nil, err
	}

	task, err := tasks.GetByID(ctx, taskID)
	if errors.Is(err, repo.ErrNotFound) {
		// 包一层 ErrNotFound 哨兵：调用方（如 checkRunningTasks）要能区分
		// 「任务已删除」和「查询失败」，后者绝不能当成删除处理。
		return nil, fmt.Errorf("任务不存在: %w", repo.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("查询任务失败: %w", err)
	}
	return task, nil
}

// ListTasks lists tasks with filtering and pagination
func (s *TaskService) ListTasksCursor(workspaceID, taskType, status string, projectID int64, cursor string, pageSize int) ([]*models.Task, string, bool, error) {
	ctx, cancel := dbCtx()
	defer cancel()
	tasks, _, err := s.stores()
	if err != nil {
		return nil, "", false, err
	}
	list, next, hasMore, err := tasks.ListCursor(ctx, workspaceID, taskType, status, projectID, cursor, pageSize)
	if err != nil {
		return nil, "", false, errors.New("查询任务列表失败: " + err.Error())
	}
	return list, next, hasMore, nil
}

func (s *TaskService) ListTasks(workspaceID string, taskType string, status string, projectID int64, page, pageSize int) ([]*models.Task, int64, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return nil, 0, err
	}

	list, total, err := tasks.List(ctx, workspaceID, taskType, status, projectID, page, pageSize)
	if err != nil {
		return nil, 0, errors.New("查询任务列表失败: " + err.Error())
	}
	return list, total, nil
}

// UpdateTask updates a task
func (s *TaskService) UpdateTask(taskID string, updates map[string]interface{}) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return err
	}

	fields, err := normalizeTaskUpdates(updates)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return nil
	}

	if err := tasks.UpdateFields(ctx, taskID, fields); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("任务不存在")
		}
		return errors.New("更新任务失败: " + err.Error())
	}
	return nil
}

// TouchTask 只推进 updated_at（活性心跳）。仅对 running 任务生效。
func (s *TaskService) TouchTask(taskID string) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return err
	}
	if err := tasks.TouchUpdated(ctx, taskID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("任务不存在或已结束")
		}
		return errors.New("更新任务心跳失败: " + err.Error())
	}
	return nil
}

// normalizeTaskUpdates 把调用方传进来的松散 map 归一成 tasks 表的列键。
// 旧版把 result_stats 当一个嵌套对象存，PG 里是拆开的列，所以这里要摊平。
func normalizeTaskUpdates(in map[string]interface{}) (map[string]any, error) {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch k {
		case "result_stats":
			for col, val := range flattenResultStats(v) {
				out[col] = val
			}
		case "error":
			// 旧版 failTask 写的键名是 error，实际列是 last_error
			out["last_error"] = v
		case "result_count":
			// 旧版写了个没有对应列的派生值，故意丢弃
		default:
			out[k] = v
		}
	}
	return out, nil
}

// flattenResultStats 兼容两种入参：models.TaskResultStats 结构体，或 map[string]interface{} 之类
// 的松散 map（pipeline 里用的就是后者，键名还不完全一样）。
func flattenResultStats(v any) map[string]any {
	out := map[string]any{}
	put := func(col string, val any) {
		if val != nil {
			out[col] = val
		}
	}

	switch stats := v.(type) {
	case models.TaskResultStats:
		put("total_targets", stats.TotalTargets)
		put("scanned_targets", stats.ScannedTargets)
		put("discovered_assets", stats.DiscoveredAssets)
		put("discovered_vulns", stats.DiscoveredVulns)
		put("discovered_ports", stats.DiscoveredPorts)
		put("last_scanned_index", stats.LastScannedIndex)
		put("completed_stages", stats.CompletedStages)
	case *models.TaskResultStats:
		if stats != nil {
			return flattenResultStats(*stats)
		}
	case map[string]any:
		for k, val := range stats {
			switch k {
			// 旧版 map[string]interface{} 里有 result_stats 内层键；只有能对上列名的才落库
			case "total_targets", "scanned_targets", "discovered_assets",
				"discovered_vulns", "discovered_ports", "last_scanned_index":
				put(k, val)
			case "completed_stages":
				put("completed_stages", val)
			}
		}
	case map[string]int:
		for k, val := range stats {
			switch k {
			case "total_targets", "scanned_targets", "discovered_assets",
				"discovered_vulns", "discovered_ports", "last_scanned_index":
				put(k, val)
			}
		}
	}
	return out
}

// DeleteTask deletes a task
func (s *TaskService) DeleteTask(taskID string) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return err
	}

	// 运行中的任务先取消，避免 worker 还在跑而记录已被删
	if task, err := tasks.GetByID(ctx, taskID); err == nil && task.Status == models.TaskStatusRunning {
		_ = s.CancelTask(taskID)
	}

	if err := tasks.Delete(ctx, taskID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("任务不存在")
		}
		return errors.New("删除任务失败: " + err.Error())
	}
	return nil
}

// StartTask starts a pending task
func (s *TaskService) StartTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}

	if task.Status != models.TaskStatusPending && task.Status != models.TaskStatusPaused {
		return errors.New("任务状态不允许启动")
	}

	if err := s.UpdateTask(taskID, map[string]interface{}{
		"status":     models.TaskStatusRunning,
		"started_at": time.Now(),
	}); err != nil {
		return err
	}

	task.Status = models.TaskStatusRunning
	s.enqueueTask(task)

	return nil
}

// PauseTask pauses a running task
func (s *TaskService) PauseTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}

	if task.Status != models.TaskStatusRunning {
		return errors.New("只能暂停正在运行的任务")
	}

	if err := s.UpdateTask(taskID, map[string]interface{}{
		"status": models.TaskStatusPaused,
	}); err != nil {
		return err
	}
	s.discardQueued(taskID)
	return nil
}

// ResumeTask resumes a paused task
func (s *TaskService) ResumeTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}

	if task.Status != models.TaskStatusPaused {
		return errors.New("只能恢复已暂停的任务")
	}

	if err := s.UpdateTask(taskID, map[string]interface{}{
		"status": models.TaskStatusRunning,
	}); err != nil {
		return err
	}

	task.Status = models.TaskStatusRunning
	s.enqueueTask(task)
	return nil
}

// CancelTask cancels a task
func (s *TaskService) CancelTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}

	if task.Status == models.TaskStatusCompleted {
		return errors.New("已完成的任务不能取消")
	}

	if err := s.UpdateTask(taskID, map[string]interface{}{
		"status": models.TaskStatusCancelled,
	}); err != nil {
		return err
	}
	s.discardQueued(taskID)
	return nil
}

// RetryTask retries a failed or cancelled task (继续从断点处扫描)
func (s *TaskService) RetryTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}

	if task.Status != models.TaskStatusFailed && task.Status != models.TaskStatusCancelled {
		return errors.New("只能重试失败或已取消的任务")
	}

	// 保留已有的扫描进度，从断点继续
	if err := s.UpdateTask(taskID, map[string]interface{}{
		"status":      models.TaskStatusPending,
		"retry_count": task.RetryCount + 1,
		"last_error":  "",
	}); err != nil {
		return err
	}

	task.Status = models.TaskStatusPending
	s.enqueueTask(task)
	return nil
}

// RescanTask 重新扫描已完成的任务（从头开始或继续未完成部分）
func (s *TaskService) RescanTask(taskID string, fromScratch bool) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}

	if task.Status != models.TaskStatusCompleted && task.Status != models.TaskStatusFailed && task.Status != models.TaskStatusCancelled {
		return errors.New("只能重新扫描已完成、失败或已取消的任务")
	}

	updates := map[string]interface{}{
		"status":      models.TaskStatusPending,
		"retry_count": task.RetryCount + 1,
		"last_error":  "",
	}

	if fromScratch {
		// 从头开始扫描，重置所有进度
		updates["progress"] = 0
		updates["result_stats"] = models.TaskResultStats{
			TotalTargets:     len(task.Targets),
			ScannedTargets:   0,
			DiscoveredAssets: 0,
			DiscoveredVulns:  0,
			DiscoveredPorts:  0,
			LastScannedIndex: 0,
			CompletedStages:  []string{},
		}
	}

	if err := s.UpdateTask(taskID, updates); err != nil {
		return err
	}

	task.Status = models.TaskStatusPending
	s.enqueueTask(task)
	return nil
}

// UpdateTaskProgress updates task progress
func (s *TaskService) UpdateTaskProgress(taskID string, progress int, stats models.TaskResultStats) error {
	updates := map[string]interface{}{
		"progress":     progress,
		"result_stats": stats,
	}

	if progress >= 100 {
		updates["status"] = models.TaskStatusCompleted
		updates["completed_at"] = time.Now()
	}

	return s.UpdateTask(taskID, updates)
}

// FailTask marks a task as failed
func (s *TaskService) FailTask(taskID string, errorMsg string) error {
	return s.UpdateTask(taskID, map[string]interface{}{
		"status":     models.TaskStatusFailed,
		"last_error": errorMsg,
	})
}

// GetTaskStats returns task statistics
func (s *TaskService) GetTaskStats(workspaceID string) (map[string]interface{}, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return nil, err
	}

	counts, err := tasks.StatusCounts(ctx, workspaceID)
	if err != nil {
		return nil, errors.New("统计失败: " + err.Error())
	}

	total := 0
	for _, n := range counts {
		total += n
	}

	stats := map[string]interface{}{
		"total":     total,
		"running":   counts[string(models.TaskStatusRunning)],
		"completed": counts[string(models.TaskStatusCompleted)],
		"failed":    counts[string(models.TaskStatusFailed)],
		"pending":   counts[string(models.TaskStatusPending)],
		"by_status": counts,
	}
	return stats, nil
}

// enqueueScan 把扫描任务放进 River。River 未初始化时退回旧的 task_jobs 实现，
// 仅用于测试/工具进程；生产启动时 main 会保证 ScanQueue 就绪。
func (s *TaskService) enqueueScan(ctx context.Context, task *models.Task, jobs repo.JobRepo) error {
	if q := DefaultScanQueue(); q != nil {
		return q.Enqueue(ctx, task.ID.Hex(), 100)
	}
	log.Printf("[TaskService] 扫描队列未初始化，任务 %s 回退到 task_jobs", task.ID.Hex())
	_, err := jobs.Enqueue(ctx, repo.EnqueueJobInput{
		TaskID:   task.ID.Hex(),
		Kind:     repo.JobKindScan,
		Priority: 100,
		Payload:  jobPayload(task.Type),
	})
	return err
}

// enqueueTask 把任务重新放进扫描队列。失败只记日志：这里是状态流转的收尾，
// 调用方拿到的错误应该反映状态变更本身是否成功。
func (s *TaskService) enqueueTask(task *models.Task) {
	ctx, cancel := dbCtx()
	defer cancel()

	_, jobs, err := s.stores()
	if err != nil {
		log.Printf("[TaskService] 入队失败（数据层未就绪）: %v", err)
		return
	}
	if err := s.enqueueScan(ctx, task, jobs); err != nil {
		log.Printf("[TaskService] 任务 %s 入队失败: %v", task.ID.Hex(), err)
		return
	}
	log.Printf("[TaskService] 任务 %s 已入队", task.ID.Hex())
}

// discardQueued 在暂停/取消时清掉还没被领取的作业，避免取消后又被执行。
func (s *TaskService) discardQueued(taskID string) {
	ctx, cancel := dbCtx()
	defer cancel()

	// River 是扫描作业的主队列；running 也一起取消，避免暂停/取消后留下僵尸 job。
	if q := DefaultScanQueue(); q != nil {
		if n, err := q.CancelAll(ctx, taskID); err != nil {
			log.Printf("[TaskService] 取消任务 %s 的 River 作业失败: %v", taskID, err)
		} else if n > 0 {
			log.Printf("[TaskService] 任务 %s 已取消 %d 个 River 作业（含运行中）", taskID, n)
		}
	}

	_, jobs, err := s.stores()
	if err != nil {
		return
	}
	if n, err := jobs.DiscardQueuedForTask(ctx, taskID); err != nil {
		log.Printf("[TaskService] 清理任务 %s 的旧排队作业失败: %v", taskID, err)
	} else if n > 0 {
		log.Printf("[TaskService] 任务 %s 已丢弃 %d 个旧排队作业", taskID, n)
	}
	NotifyTaskCancel(taskID)
}

// CreateTaskTemplate creates a task template
func (s *TaskService) CreateTaskTemplate(template *models.TaskTemplate) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return err
	}

	if template.ID.IsZero() {
		template.ID = oid.NewObjectID()
	}
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()

	if err := tasks.CreateTemplate(ctx, template); err != nil {
		return errors.New("创建任务模板失败: " + err.Error())
	}
	return nil
}

// ListTaskTemplates lists task templates
func (s *TaskService) ListTaskTemplates(workspaceID string, isPublic *bool) ([]*models.TaskTemplate, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return nil, err
	}

	list, err := tasks.ListTemplates(ctx, workspaceID, isPublic)
	if err != nil {
		return nil, errors.New("查询任务模板失败: " + err.Error())
	}
	return list, nil
}

// GetTaskTemplate gets a task template by ID
func (s *TaskService) GetTaskTemplate(templateID string) (*models.TaskTemplate, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return nil, err
	}

	t, err := tasks.GetTemplate(ctx, templateID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, errors.New("模板不存在")
	}
	if err != nil {
		return nil, errors.New("查询模板失败: " + err.Error())
	}
	return t, nil
}

// UpdateTaskTemplate updates an existing task template
func (s *TaskService) UpdateTaskTemplate(templateID string, patch *models.TaskTemplate) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return err
	}

	existing, err := tasks.GetTemplate(ctx, templateID)
	if errors.Is(err, repo.ErrNotFound) {
		return errors.New("模板不存在")
	}
	if err != nil {
		return errors.New("查询模板失败: " + err.Error())
	}

	existing.Name = patch.Name
	existing.Description = patch.Description
	existing.Type = patch.Type
	existing.Config = patch.Config
	existing.IsPublic = patch.IsPublic
	existing.UpdatedAt = time.Now()

	if err := tasks.UpdateTemplate(ctx, existing); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("模板不存在")
		}
		return errors.New("更新任务模板失败: " + err.Error())
	}
	return nil
}

// DeleteTaskTemplate deletes a task template
func (s *TaskService) DeleteTaskTemplate(templateID string) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return err
	}

	if err := tasks.DeleteTemplate(ctx, templateID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("模板不存在")
		}
		return errors.New("删除模板失败: " + err.Error())
	}
	return nil
}

// AddLogsBatch 批量写运行明细日志（master 直写 / worker 经网关批量上报）。
func (s *TaskService) AddLogsBatch(ctx context.Context, taskID string, rows []repo.TaskLogInsert) error {
	tasks, _, err := s.stores()
	if err != nil {
		return err
	}
	return tasks.AddLogsBatch(ctx, taskID, rows)
}

// ClaimExecution 执行认领：原子抢占 executor_id，已被认领返回 false。
func (s *TaskService) ClaimExecution(ctx context.Context, taskID, executorID, claimNodeID string) (bool, error) {
	tasks, _, err := s.stores()
	if err != nil {
		return false, err
	}
	return tasks.ClaimExecution(ctx, taskID, executorID, claimNodeID)
}

// ReleaseExecution 释放执行认领。
func (s *TaskService) ReleaseExecution(ctx context.Context, taskID string) error {
	tasks, _, err := s.stores()
	if err != nil {
		return err
	}
	return tasks.ReleaseExecution(ctx, taskID)
}

// AddLogCategory 带功能分类的动作日志（worker 经网关上报 / master 侧埋点共用）。
func (s *TaskService) AddLogCategory(ctx context.Context, taskID, category, level, message, detail string) error {
	tasks, _, err := s.stores()
	if err != nil {
		return err
	}
	return tasks.AddLogCategory(ctx, taskID, category, level, message, detail)
}

// AddTaskLog adds a log entry for a task
func (s *TaskService) AddTaskLog(taskID string, level string, message string, detail string) error {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return err
	}

	if err := tasks.AddLog(ctx, taskID, level, message, detail); err != nil {
		return errors.New("添加日志失败: " + err.Error())
	}
	return nil
}

// GetTaskLogs gets logs for a task
func (s *TaskService) GetTaskLogs(taskID string, page, pageSize int) ([]*models.TaskLog, int64, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	tasks, _, err := s.stores()
	if err != nil {
		return nil, 0, err
	}

	logs, total, err := tasks.ListLogs(ctx, taskID, page, pageSize)
	if err != nil {
		return nil, 0, errors.New("查询日志失败: " + err.Error())
	}
	return logs, total, nil
}
