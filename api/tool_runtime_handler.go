package api

import (
	"strings"

	"github.com/c1ayooo/4zreark/internal/toolruntime"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// ToolRuntimeHandler 管理外部扫描工具二进制（gogo/spray/katana/rem）。
type ToolRuntimeHandler struct {
	svc *service.ToolRuntimeService
}

func NewToolRuntimeHandler() *ToolRuntimeHandler {
	return &ToolRuntimeHandler{svc: service.GetToolRuntimeService()}
}

// List 全部工具状态（含 nuclei 摘要）
// @Router /api/tools [get]
func (h *ToolRuntimeHandler) List(c *gin.Context) {
	utils.Success(c, h.svc.Status(c.Request.Context()))
}

// Check 查询单个工具上游最新版本
// @Router /api/tools/:name/check [post]
func (h *ToolRuntimeHandler) Check(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	st, err := h.svc.Check(c.Request.Context(), name)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, st)
}

// Update 安装/更新单个工具
// @Router /api/tools/:name/update [post]
func (h *ToolRuntimeHandler) Update(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	var req struct {
		Force bool `json:"force"`
	}
	_ = c.ShouldBindJSON(&req)
	st, err := h.svc.Update(c.Request.Context(), name, req.Force)
	if err != nil {
		utils.InternalError(c, "更新 "+name+" 失败: "+err.Error())
		return
	}
	utils.SuccessWithMessage(c, "更新完成", st)
}

// Rollback 回滚到上一个版本
// @Router /api/tools/:name/rollback [post]
func (h *ToolRuntimeHandler) Rollback(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	st, err := h.svc.Rollback(c.Request.Context(), name)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已回滚", st)
}

// History 更新历史
// @Router /api/tools/:name/history [get]
func (h *ToolRuntimeHandler) History(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	recs, err := h.svc.History(c.Request.Context(), name)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, recs)
}

// UpdateSettings 修改工具设置（pinned_version / auto_update / check_interval_hours）
// @Router /api/tools/:name/settings [put]
func (h *ToolRuntimeHandler) UpdateSettings(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	var req struct {
		PinnedVersion      *string `json:"pinned_version"`
		AutoUpdate         *bool   `json:"auto_update"`
		CheckIntervalHours *int    `json:"check_interval_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不是合法 JSON")
		return
	}
	st, err := h.svc.ApplySettings(c.Request.Context(), name, func(ts *toolruntime.ToolState) {
		if req.PinnedVersion != nil {
			ts.PinnedVersion = strings.TrimSpace(*req.PinnedVersion)
		}
		if req.AutoUpdate != nil {
			ts.AutoUpdate = *req.AutoUpdate
		}
		if req.CheckIntervalHours != nil {
			ts.CheckIntervalHours = *req.CheckIntervalHours
		}
	})
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "设置已保存", st)
}
