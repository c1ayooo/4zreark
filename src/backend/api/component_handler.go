package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// ComponentHandler 组件 → CVE 查询与漏洞证据质量体检。
type ComponentHandler struct {
	svc *service.ComponentService
}

func NewComponentHandler() *ComponentHandler {
	return &ComponentHandler{svc: service.NewComponentService()}
}

// CVEs 查询组件已知 CVE
// @Router /api/components/cves [get]
func (h *ComponentHandler) CVEs(c *gin.Context) {
	product := c.Query("product")
	if product == "" {
		utils.BadRequest(c, "product 不能为空")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	list, err := h.svc.CVEs(c.Request.Context(), product, limit)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, gin.H{"product": product, "items": list, "total": len(list)})
}

// EvidenceQuality 漏洞证据质量体检
// @Router /api/components/evidence-quality [get]
func (h *ComponentHandler) EvidenceQuality(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	list, err := h.svc.EvidenceQuality(c.Request.Context(), c.Query("workspace_id"), limit)
	if err != nil {
		utils.InternalError(c, "证据质量检查失败: "+err.Error())
		return
	}
	utils.Success(c, list)
}
