package api

import (
	"context"
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// EnterpriseHandler 企业身份线索：手工维护、数据源采集、与数字资产名单对齐。
type EnterpriseHandler struct {
	svc *service.EnterpriseService
}

func NewEnterpriseHandler() *EnterpriseHandler {
	return &EnterpriseHandler{svc: service.NewEnterpriseService()}
}

// List GET /api/enterprise-entities?project_id=&q=&status=&page=&page_size=
func (h *EnterpriseHandler) List(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	minCap, _ := strconv.ParseFloat(c.Query("min_capital_wan"), 64)
	items, total, err := h.svc.List(c.Request.Context(), repo.EnterpriseFilter{
		ProjectID: projectID, Query: c.Query("q"), Status: c.Query("status"),
		MinRegisteredCapitalWan: minCap,
		Page:                    page, PageSize: pageSize,
	})
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithPagination(c, items, total, page, pageSize)
}

// Upsert POST /api/enterprise-entities
func (h *EnterpriseHandler) Upsert(c *gin.Context) {
	var body struct {
		ProjectID int64 `json:"project_id"`
		repo.EnterpriseInput
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	entity, err := h.svc.Upsert(c.Request.Context(), body.ProjectID, body.EnterpriseInput)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "企业线索已保存", entity)
}

// Delete DELETE /api/enterprise-entities/:id
func (h *EnterpriseHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法企业 ID")
		return
	}
	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "企业线索不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", nil)
}

// Import POST /api/enterprise-entities/import
func (h *EnterpriseHandler) Import(c *gin.Context) {
	var body struct {
		ProjectID int64                  `json:"project_id"`
		Source    string                 `json:"source"`
		Items     []repo.EnterpriseInput `json:"items"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if body.Source == "" {
		body.Source = "import"
	}
	inserted, updated, err := h.svc.Import(c.Request.Context(), body.ProjectID, body.Items, body.Source)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "企业线索已导入", gin.H{
		"inserted": inserted, "updated": updated, "total": len(body.Items),
	})
}

// AlignedAssets GET /api/enterprise-entities/:id/assets
func (h *EnterpriseHandler) AlignedAssets(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法企业 ID")
		return
	}
	entity, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "企业线索不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	items, err := h.svc.AlignedAssets(c.Request.Context(), entity.ProjectID, entity.Name)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"entity": entity, "items": items, "total": len(items)})
}

// Providers GET /api/enterprise-entities/providers
func (h *EnterpriseHandler) Providers(c *gin.Context) {
	utils.Success(c, gin.H{"items": h.svc.Providers()})
}

// Collect POST /api/enterprise-entities/collect
func (h *EnterpriseHandler) Collect(c *gin.Context) {
	var body service.EnterpriseCollectInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.Collect(c.Request.Context(), body)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			utils.BadRequest(c, "企业数据源响应超时")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "采集完成", res)
}

// SearchProvider POST /api/enterprise-entities/search
// 只读：按企业名搜索上游，返回 ext_id/name 供下一步深度采集选择。
func (h *EnterpriseHandler) SearchProvider(c *gin.Context) {
	var body service.EnterpriseCollectInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	refs, err := h.svc.SearchProvider(c.Request.Context(), body)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": refs, "total": len(refs)})
}

// Discover POST /api/enterprise-entities/discover
// 启动后台 BFS 采集（分支/投资逐层展开），立即返回任务。
func (h *EnterpriseHandler) Discover(c *gin.Context) {
	var body service.EnterpriseDiscoverInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	body.Owner = c.GetString("username")
	job, err := h.svc.Discover(c.Request.Context(), body)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "采集任务已启动", job)
}

// Jobs GET /api/enterprise-entities/jobs?project_id=&limit=
func (h *EnterpriseHandler) Jobs(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	jobs, err := h.svc.Jobs(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": jobs, "total": len(jobs)})
}

// GetJob GET /api/enterprise-entities/jobs/:id
func (h *EnterpriseHandler) GetJob(c *gin.Context) {
	job, err := h.svc.Job(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "采集任务不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, job)
}

// CancelJob POST /api/enterprise-entities/jobs/:id/cancel
func (h *EnterpriseHandler) CancelJob(c *gin.Context) {
	ok, err := h.svc.CancelJob(c.Param("id"))
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if !ok {
		utils.BadRequest(c, "任务不在运行中（或已结束）")
		return
	}
	utils.SuccessWithMessage(c, "已请求取消", gin.H{"id": c.Param("id")})
}

// Candidates GET /api/enterprise-entities/candidates?project_id=&status=&limit=
func (h *EnterpriseHandler) Candidates(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	items, err := h.svc.Candidates(c.Request.Context(), projectID, c.Query("status"), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}
