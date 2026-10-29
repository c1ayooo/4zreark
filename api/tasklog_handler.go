package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// TaskLogHandler 任务日志（统一动作日志）：跨源聚合、按功能筛选、自动清空。
type TaskLogHandler struct {
	svc *service.TaskLogService
}

func NewTaskLogHandler() *TaskLogHandler { return &TaskLogHandler{svc: service.NewTaskLogService()} }

// List GET /api/task-logs?project_id=&category=&level=&q=&page=&page_size=
func (h *TaskLogHandler) List(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	rows, total, err := h.svc.List(c.Request.Context(), service.TaskLogFilter{
		ProjectID: projectID,
		Category:  c.Query("category"),
		Level:     c.Query("level"),
		Query:     c.Query("q"),
		Page:      page,
		PageSize:  pageSize,
	})
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithPagination(c, rows, total, page, pageSize)
}

// GetSettings GET /api/task-logs/settings — 自动清空时段（天）。
func (h *TaskLogHandler) GetSettings(c *gin.Context) {
	utils.Success(c, gin.H{"retention_days": h.svc.RetentionDays(c.Request.Context())})
}

// UpdateSettings PUT /api/task-logs/settings — 设置自动清空时段并立即清理一次。
func (h *TaskLogHandler) UpdateSettings(c *gin.Context) {
	var body struct {
		RetentionDays int `json:"retention_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.RetentionDays < 1 || body.RetentionDays > 365 {
		utils.BadRequest(c, "retention_days 必须是 1–365")
		return
	}
	purged, err := h.svc.SetRetentionDays(c.Request.Context(), body.RetentionDays)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "自动清空时段已保存并按新时段清理", gin.H{
		"retention_days": body.RetentionDays, "purged": purged,
	})
}

// Purge POST /api/task-logs/purge — 立即清空。
func (h *TaskLogHandler) Purge(c *gin.Context) {
	n, err := h.svc.PurgeNow(c.Request.Context())
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已清空", gin.H{"purged": n})
}
