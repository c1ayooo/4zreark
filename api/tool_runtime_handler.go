package api

import (
	"context"
	"strings"
	"time"

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

// Installed 检索平台项目内部已安装的工具（支持 q/source/in_project/managed）。
// include_external=1 时把系统 PATH 等外部候选并入结果，默认单列在 external 字段。
// @Router /api/tools/installed [get]
func (h *ToolRuntimeHandler) Installed(c *gin.Context) {
	f := toolruntime.InstalledFilter{
		Query:     strings.TrimSpace(c.Query("q")),
		Source:    strings.TrimSpace(c.Query("source")),
		InProject: queryBool(c, "in_project"),
		Managed:   queryBool(c, "managed"),
	}
	includeExternal := false
	if v := queryBool(c, "include_external"); v != nil {
		includeExternal = *v
	}
	utils.Success(c, h.svc.InstalledTools(c.Request.Context(), f, includeExternal))
}

// Ensure 立即检测并补装项目内缺失的工具。
// @Router /api/tools/ensure-installed [post]
func (h *ToolRuntimeHandler) Ensure(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer cancel()
	utils.SuccessWithMessage(c, "已巡检项目内工具", h.svc.EnsureMissing(ctx))
}

// Check 查询单个工具上游最新版本
// @Router /api/tools/:name/check [post]
func (h *ToolRuntimeHandler) Check(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if name == "browser" {
		utils.BadRequest(c, "browser 非 GitHub release 工具：更新检测已内置于 browser 条目（update_available），无需上游查询")
		return
	}
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
	if name == "browser" {
		// 自带浏览器：重新自举到当前平台期望的 revision（已是最新的话快速返回）
		st, err := h.svc.UpdateBrowser(c.Request.Context())
		if err != nil {
			utils.InternalError(c, "更新 browser 失败: "+err.Error())
			return
		}
		utils.SuccessWithMessage(c, "浏览器已更新", st)
		return
	}
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

func queryBool(c *gin.Context, key string) *bool {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return nil
	}
	v := raw == "1" || strings.EqualFold(raw, "true") || strings.EqualFold(raw, "yes")
	return &v
}
