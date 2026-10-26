package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// AssessmentHandler 采集完成综合评估：最近评估 + 资产面趋势（快照）。
type AssessmentHandler struct{}

func NewAssessmentHandler() *AssessmentHandler { return &AssessmentHandler{} }

// GetProjectAssessment GET /api/projects/:id/assessment
func (h *AssessmentHandler) GetProjectAssessment(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("trend_limit", "30"))
	latest, trend, err := service.ProjectAssessmentTrend(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if latest == nil {
		utils.NotFound(c, "该项目还没有评估快照（完成一次采集后生成）")
		return
	}
	utils.Success(c, gin.H{"latest": latest, "trend": trend})
}
