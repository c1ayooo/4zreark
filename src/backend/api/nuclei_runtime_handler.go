package api

import (
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// NucleiRuntimeHandler 管理 nuclei 二进制与上游模板快照。
type NucleiRuntimeHandler struct {
	svc *service.NucleiRuntimeService
}

func NewNucleiRuntimeHandler() *NucleiRuntimeHandler {
	return &NucleiRuntimeHandler{svc: service.NewNucleiRuntimeService()}
}

// Status runtime 状态
// @Router /api/nuclei/runtime/status [get]
func (h *NucleiRuntimeHandler) Status(c *gin.Context) {
	st, err := h.svc.Status(c.Request.Context())
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, st)
}

// Ensure 检查/补齐二进制与模板
// @Router /api/nuclei/runtime/ensure [post]
func (h *NucleiRuntimeHandler) Ensure(c *gin.Context) {
	auto := c.Query("auto") == "1" || c.Query("auto") == "true"
	res, err := h.svc.Ensure(c.Request.Context(), auto)
	if err != nil {
		utils.InternalError(c, "检查 nuclei 运行时失败: "+err.Error())
		return
	}
	utils.Success(c, res)
}

// Update 下载/更新二进制或模板
// @Router /api/nuclei/runtime/update [post]
func (h *NucleiRuntimeHandler) Update(c *gin.Context) {
	var req struct {
		Force         bool `json:"force"`
		BinaryOnly    bool `json:"binary_only"`
		TemplatesOnly bool `json:"templates_only"`
	}
	_ = c.ShouldBindJSON(&req)
	res, err := h.svc.Update(c.Request.Context(), req.Force, req.BinaryOnly, req.TemplatesOnly, nil)
	if err != nil {
		utils.InternalError(c, "更新 nuclei 运行时失败: "+err.Error())
		return
	}
	utils.SuccessWithMessage(c, "更新完成", res)
}

// UpdateSettings 修改运行时设置
// @Router /api/nuclei/runtime/settings [put]
func (h *NucleiRuntimeHandler) UpdateSettings(c *gin.Context) {
	var in map[string]any
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "请求体不是合法 JSON")
		return
	}
	if err := h.svc.SetSettings(in); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	st, _ := h.svc.Status(c.Request.Context())
	utils.SuccessWithMessage(c, "设置已保存", st)
}
