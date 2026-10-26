package api

import (
	"context"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/service/queue"
	"github.com/c1ayooo/4zreark/utils"
	"strconv"

	"github.com/gin-gonic/gin"
)

// QueueHandler 队列处理器（存储为 PostgreSQL 的 task_jobs，不再依赖 Redis）
type QueueHandler struct {
	taskQueue *queue.TaskQueue
}

// defaultQueueHandler 记录进程内创建的队列实例：worker 在路由注册副作用里启动，
// 优雅关停由 main 通过 StopQueueHandler 触发（否则 SIGTERM 时在跑的 handler 被硬杀）。
var defaultQueueHandler *QueueHandler

// NewQueueHandler 创建队列处理器
func NewQueueHandler(config *queue.QueueConfig) (*QueueHandler, error) {
	taskQueue, err := queue.NewTaskQueue(config)
	if err != nil {
		return nil, err
	}

	// 注册内置任务处理器
	registerBuiltinHandlers(taskQueue)

	// 启动工作者
	taskQueue.Start()

	h := &QueueHandler{
		taskQueue: taskQueue,
	}
	defaultQueueHandler = h
	return h, nil
}

// StopQueueHandler 停止通用队列 worker（幂等；未创建时为 no-op）。
func StopQueueHandler() {
	if defaultQueueHandler != nil {
		defaultQueueHandler.taskQueue.Stop()
	}
}

// registerBuiltinHandlers 注册内置任务处理器
func registerBuiltinHandlers(q *queue.TaskQueue) {
	// 示例: 端口扫描任务
	q.RegisterHandler("port_scan", func(ctx context.Context, task *queue.Task) (interface{}, error) {
		// 从 payload 获取参数
		target, _ := task.Payload["target"].(string)
		// ports, _ := task.Payload["ports"].(string)

		// 执行扫描 (这里是简化示例)
		result := map[string]interface{}{
			"target": target,
			"status": "completed",
		}

		return result, nil
	})

	// 示例: 漏洞扫描任务
	q.RegisterHandler("vuln_scan", func(ctx context.Context, task *queue.Task) (interface{}, error) {
		target, _ := task.Payload["target"].(string)

		result := map[string]interface{}{
			"target": target,
			"status": "completed",
		}

		return result, nil
	})

	// 示例: 子域名枚举任务
	q.RegisterHandler("subdomain_enum", func(ctx context.Context, task *queue.Task) (interface{}, error) {
		domain, _ := task.Payload["domain"].(string)

		result := map[string]interface{}{
			"domain": domain,
			"status": "completed",
		}

		return result, nil
	})
}

// GetTaskQueue 获取任务队列实例
func (h *QueueHandler) GetTaskQueue() *queue.TaskQueue {
	return h.taskQueue
}

// GetStats 获取队列统计
// @Summary 获取队列统计信息
// @Tags Queue
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/queue/stats [get]
func (h *QueueHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	stats, err := h.taskQueue.GetStats(ctx)
	if err != nil {
		utils.InternalError(c, "获取统计失败: "+err.Error())
		return
	}

	utils.Success(c, stats)
}

// EnqueueTask 添加任务
// @Summary 添加任务到队列
// @Tags Queue
// @Security ApiKeyAuth
// @Param task body EnqueueRequest true "任务信息"
// @Success 200 {object} utils.Response
// @Router /api/queue/tasks [post]
func (h *QueueHandler) EnqueueTask(c *gin.Context) {
	var req struct {
		Type     string                 `json:"type" binding:"required"`
		Payload  map[string]interface{} `json:"payload"`
		Priority int                    `json:"priority"`
		Delay    int                    `json:"delay"` // 延迟秒数
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	// 未注册 handler 的类型入队只会空转退避后进死信，入口直接拒绝。
	if !h.taskQueue.HasHandler(req.Type) {
		utils.BadRequest(c, "不支持的任务类型: "+req.Type+"（可用: "+strings.Join(h.taskQueue.RegisteredTypes(), ", ")+"）")
		return
	}

	ctx := c.Request.Context()
	var task *queue.Task
	var err error

	if req.Delay > 0 {
		task, err = h.taskQueue.Schedule(ctx, req.Type, req.Payload, time.Duration(req.Delay)*time.Second)
	} else if req.Priority != 0 {
		task, err = h.taskQueue.EnqueueWithPriority(ctx, req.Type, req.Payload, req.Priority)
	} else {
		task, err = h.taskQueue.Enqueue(ctx, req.Type, req.Payload)
	}

	if err != nil {
		utils.InternalError(c, "添加任务失败: "+err.Error())
		return
	}

	utils.SuccessWithMessage(c, "任务已添加", map[string]interface{}{
		"task_id": task.ID,
		"type":    task.Type,
		"status":  task.Status,
	})
}

// GetTaskResult 获取任务结果
// @Summary 获取任务执行结果
// @Tags Queue
// @Security ApiKeyAuth
// @Param id path string true "任务ID"
// @Success 200 {object} utils.Response
// @Router /api/queue/tasks/{id}/result [get]
func (h *QueueHandler) GetTaskResult(c *gin.Context) {
	taskID := c.Param("id")

	ctx := c.Request.Context()
	result, err := h.taskQueue.GetResult(ctx, taskID)
	if err != nil {
		utils.NotFound(c, "任务结果不存在或已过期")
		return
	}

	utils.Success(c, result)
}

// GetPendingTasks 获取待处理任务
// @Summary 获取待处理任务列表
// @Tags Queue
// @Security ApiKeyAuth
// @Param limit query int false "返回数量"
// @Success 200 {object} utils.Response
// @Router /api/queue/tasks/pending [get]
func (h *QueueHandler) GetPendingTasks(c *gin.Context) {
	limit, _ := strconv.ParseInt(c.DefaultQuery("limit", "100"), 10, 64)

	ctx := c.Request.Context()
	tasks, err := h.taskQueue.GetPendingTasks(ctx, limit)
	if err != nil {
		utils.InternalError(c, "获取任务失败: "+err.Error())
		return
	}

	utils.Success(c, tasks)
}

// GetProcessingTasks 获取处理中的任务
// @Summary 获取处理中的任务列表
// @Tags Queue
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/queue/tasks/processing [get]
func (h *QueueHandler) GetProcessingTasks(c *gin.Context) {
	ctx := c.Request.Context()
	tasks, err := h.taskQueue.GetProcessingTasks(ctx)
	if err != nil {
		utils.InternalError(c, "获取任务失败: "+err.Error())
		return
	}

	utils.Success(c, tasks)
}

// GetDeadLetterTasks 获取死信任务
// @Summary 获取死信队列任务
// @Tags Queue
// @Security ApiKeyAuth
// @Param limit query int false "返回数量"
// @Success 200 {object} utils.Response
// @Router /api/queue/tasks/deadletter [get]
func (h *QueueHandler) GetDeadLetterTasks(c *gin.Context) {
	limit, _ := strconv.ParseInt(c.DefaultQuery("limit", "100"), 10, 64)

	ctx := c.Request.Context()
	tasks, err := h.taskQueue.GetDeadLetterTasks(ctx, limit)
	if err != nil {
		utils.InternalError(c, "获取任务失败: "+err.Error())
		return
	}

	utils.Success(c, tasks)
}

// RetryDeadLetterTask 重试死信任务
// @Summary 重试死信队列中的任务
// @Tags Queue
// @Security ApiKeyAuth
// @Param id path string true "任务ID"
// @Success 200 {object} utils.Response
// @Router /api/queue/tasks/deadletter/{id}/retry [post]
func (h *QueueHandler) RetryDeadLetterTask(c *gin.Context) {
	taskID := c.Param("id")

	ctx := c.Request.Context()
	if err := h.taskQueue.RetryDeadLetter(ctx, taskID); err != nil {
		utils.NotFound(c, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "任务已重新入队", nil)
}

// ClearDeadLetter 清空死信队列
// @Summary 清空死信队列
// @Tags Queue
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/queue/tasks/deadletter [delete]
func (h *QueueHandler) ClearDeadLetter(c *gin.Context) {
	ctx := c.Request.Context()
	if err := h.taskQueue.ClearDeadLetter(ctx); err != nil {
		utils.InternalError(c, "清空失败: "+err.Error())
		return
	}

	utils.SuccessWithMessage(c, "死信队列已清空", nil)
}

// GetTaskTypes 获取支持的任务类型
// 只列已注册 handler 的类型：此前宣告的 fingerprint_scan/dir_scan 没有
// handler，提交后只会空转进死信。注意 port_scan/vuln_scan/subdomain_enum
// 目前是演示实现（直接返回 completed）；真实扫描走 /api/tasks。
// @Summary 获取支持的任务类型
// @Tags Queue
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/queue/types [get]
func (h *QueueHandler) GetTaskTypes(c *gin.Context) {
	registered := map[string]map[string]interface{}{
		"port_scan": {
			"type":           "port_scan",
			"name":           "端口扫描",
			"description":    "对目标进行端口扫描（演示实现，真实扫描走 /api/tasks）",
			"payload_schema": map[string]string{"target": "目标IP或域名", "ports": "端口范围，如 1-1000"},
		},
		"vuln_scan": {
			"type":           "vuln_scan",
			"name":           "漏洞扫描",
			"description":    "对目标进行漏洞扫描（演示实现，真实扫描走 /api/tasks）",
			"payload_schema": map[string]string{"target": "目标URL", "poc_ids": "POC ID列表 (可选)"},
		},
		"subdomain_enum": {
			"type":           "subdomain_enum",
			"name":           "子域名枚举",
			"description":    "对域名进行子域名枚举（演示实现，真实扫描走 /api/tasks）",
			"payload_schema": map[string]string{"domain": "目标域名", "mode": "扫描模式: quick/full"},
		},
	}

	types := make([]map[string]interface{}, 0, len(registered))
	for _, t := range h.taskQueue.RegisteredTypes() {
		if meta, ok := registered[t]; ok {
			types = append(types, meta)
		} else {
			types = append(types, map[string]interface{}{"type": t, "name": t, "description": "自定义任务类型"})
		}
	}

	utils.Success(c, types)
}

// GetWorkerStatus 获取Worker状态
// @Summary 获取Worker状态
// @Tags Queue
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/queue/workers [get]
func (h *QueueHandler) GetWorkerStatus(c *gin.Context) {
	ctx := c.Request.Context()

	status, err := h.taskQueue.GetWorkerStatus(ctx)
	if err != nil {
		utils.InternalError(c, "获取Worker状态失败: "+err.Error())
		return
	}

	utils.Success(c, status)
}
