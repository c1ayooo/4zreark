package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// CollectOverviewHandler 项目采集概览：采集到了什么 / 任务跑得怎么样 / 有没有问题。
type CollectOverviewHandler struct {
	svc *service.EnterpriseService
}

func NewCollectOverviewHandler() *CollectOverviewHandler {
	return &CollectOverviewHandler{svc: service.NewEnterpriseService()}
}

// GetCollectOverview GET /api/projects/:id/collect-overview
func (h *CollectOverviewHandler) GetCollectOverview(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	out, err := h.svc.BuildCollectOverview(c.Request.Context(), projectID)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, out)
}
