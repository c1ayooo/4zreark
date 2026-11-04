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
//
// auto_promote=true 时，查询完成后自动把备案域名转成 domain 种子并建计划，
// 调用方不需要再手工导出域名再调 /seeds/batch。
func (h *ICPHandler) Enqueue(c *gin.Context) {
	var body struct {
		ProjectID   int64  `json:"project_id"`
		Query       string `json:"query"`
		ServiceType int    `json:"service_type"`
		PageSize    int    `json:"page_size"`
		AutoPromote bool   `json:"auto_promote"`
		IntervalHours int  `json:"promote_interval_hours"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	q, err := h.svc.Enqueue(c.Request.Context(), body.ProjectID, body.Query,
		body.ServiceType, body.PageSize, body.AutoPromote, body.IntervalHours)
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

// Promote POST /api/icp/queries/:id/promote
//
// 把已完成的查询结果里去重后的备案域名转成 domain 种子（可选同时建计划）。
// 幂等：重复调用只补新增的域名，已存在的种子不会重复创建。
func (h *ICPHandler) Promote(c *gin.Context) {
	var body struct {
		IntervalHours int `json:"interval_hours"`
	}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			utils.BadRequest(c, "参数错误: "+err.Error())
			return
		}
	}
	res, err := h.svc.PromoteToSeeds(c.Request.Context(), c.Param("id"), body.IntervalHours)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "查询任务不存在")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "备案域名已转成种子", res)
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
