package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// ICPHandler 工信部 ICP 官方备案查询（异步、限速、独立队列）。
type ICPHandler struct {
	svc *service.ICPService
}

func NewICPHandler() *ICPHandler {
	return &ICPHandler{svc: service.DefaultICPService()}
}

// Enqueue POST /api/icp/queries
func (h *ICPHandler) Enqueue(c *gin.Context) {
	var body struct {
		ProjectID   int64  `json:"project_id"`
		Query       string `json:"query"`
		ServiceType int    `json:"service_type"`
		PageSize    int    `json:"page_size"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	q, err := h.svc.Enqueue(c.Request.Context(), body.ProjectID, body.Query, body.ServiceType, body.PageSize)
	if err != nil {
		if errors.Is(err, service.ErrICPQueueFull) {
			utils.Error(c, utils.ErrCodeTooManyRequests, err.Error())
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "查询已入队", q)
}

// List GET /api/icp/queries?project_id=&limit=
func (h *ICPHandler) List(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	items, err := h.svc.List(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// Get GET /api/icp/queries/:id?limit=
func (h *ICPHandler) Get(c *gin.Context) {
	q, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "查询任务不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "500"))
	filings, err := h.svc.Filings(c.Request.Context(), q.ID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"query": q, "filings": filings, "total": len(filings)})
}

// Cancel POST /api/icp/queries/:id/cancel
func (h *ICPHandler) Cancel(c *gin.Context) {
	if !h.svc.Cancel(c.Param("id")) {
		utils.BadRequest(c, "任务不在排队或运行中，无法取消")
		return
	}
	utils.SuccessWithMessage(c, "已请求取消", gin.H{"id": c.Param("id")})
}
