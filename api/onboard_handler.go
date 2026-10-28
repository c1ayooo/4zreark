package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// OnboardHandler 项目一键侦察：公司名 → 企业采集 → 采集完成后自动创建扫描任务。
type OnboardHandler struct {
	svc *service.EnterpriseService
}

func NewOnboardHandler() *OnboardHandler {
	return &OnboardHandler{svc: service.NewEnterpriseService()}
}

// Onboard POST /api/projects/:id/onboard
func (h *OnboardHandler) Onboard(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	var body service.ProjectOnboardInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	body.ProjectID = projectID
	job, err := h.svc.Onboard(c.Request.Context(), body)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "一键侦察已启动：企业采集完成后将自动创建扫描任务", gin.H{
		"job": job,
	})
}
