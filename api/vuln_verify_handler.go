package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// VulnVerifyHandler 自动 nuclei 验证的入口与统计。
type VulnVerifyHandler struct {
	svc *service.VulnVerifyService
}

func NewVulnVerifyHandler() *VulnVerifyHandler {
	return &VulnVerifyHandler{svc: service.NewVulnVerifyService()}
}

// Stats 近 N 天自动验证统计
// @Router /api/vuln-verify/stats [get]
func (h *VulnVerifyHandler) Stats(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	st, err := h.svc.Stats(c.Request.Context(), days)
	if err != nil {
		utils.InternalError(c, "读取自动验证统计失败: "+err.Error())
		return
	}
	utils.Success(c, st)
}

// Enqueue 手动投递一次自动验证
// @Router /api/vuln-verify/enqueue [post]
func (h *VulnVerifyHandler) Enqueue(c *gin.Context) {
	var req struct {
		ProjectID string `json:"project_id" binding:"required"`
		Target    string `json:"target" binding:"required"`
		Product   string `json:"product" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	h.svc.Enqueue(req.ProjectID, req.Target, req.Product)
	utils.SuccessWithMessage(c, "已投递（未启用/出 scope 时会被跳过）", nil)
}
