package api

import (
	"errors"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"strconv"
)

// CollectionHandler 暴露信息收集计划与阶段账本（只读）。
type CollectionHandler struct {
	store *repo.CollectionRepo
}

func NewCollectionHandler() *CollectionHandler {
	return &CollectionHandler{store: repo.NewCollectionRepo()}
}

// ListPlans GET /api/collection/plans
func (h *CollectionHandler) ListPlans(c *gin.Context) {
	if h.store == nil {
		utils.InternalError(c, "数据层未初始化")
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	status := c.Query("status")
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	plans, total, err := h.store.ListPlans(c.Request.Context(), projectID, status, page, pageSize)
	if err != nil {
		utils.InternalError(c, "查询信息收集计划失败: "+err.Error())
		return
	}
	utils.SuccessWithPagination(c, plans, total, page, pageSize)
}

// GetPlan GET /api/collection/plans/:id
// 返回计划 + 阶段时间线（含子任务名称/状态/进度），前端一次拉齐。
func (h *CollectionHandler) GetPlan(c *gin.Context) {
	if h.store == nil {
		utils.InternalError(c, "数据层未初始化")
		return
	}
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "计划 ID 不能为空")
		return
	}

	plan, err := h.store.GetPlan(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.NotFound(c, "信息收集计划不存在")
			return
		}
		utils.InternalError(c, "查询信息收集计划失败: "+err.Error())
		return
	}
	stages, err := h.store.ListStagesWithTask(c.Request.Context(), id)
	if err != nil {
		utils.InternalError(c, "查询阶段账本失败: "+err.Error())
		return
	}
	utils.Success(c, gin.H{"plan": plan, "stages": stages})
}
