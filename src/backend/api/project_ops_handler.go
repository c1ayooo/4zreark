package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// ProjectOpsHandler 是项目生命周期入口：采集态快照、永久删除。
type ProjectOpsHandler struct {
	ops *service.ProjectOpsService
}

func NewProjectOpsHandler() *ProjectOpsHandler {
	return &ProjectOpsHandler{ops: service.NewProjectOpsService()}
}

// CollectionState 项目采集态汇总。
// GET /api/projects/:id/collection-state
func (h *ProjectOpsHandler) CollectionState(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	state, err := h.ops.CollectionState(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "项目不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, state)
}

// DeleteProject 永久删除项目，confirm_code 必须等于项目编码。
// DELETE /api/projects/:id
func (h *ProjectOpsHandler) DeleteProject(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	var body struct {
		ConfirmCode string `json:"confirm_code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil && !errors.Is(err, io.EOF) {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	res, err := h.ops.Delete(c.Request.Context(), id, body.ConfirmCode, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrProjectInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "项目不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "项目已永久删除", res)
}

// SeedRestartHandler 是种子重建计划入口：预览拿 token，确认后执行。
type SeedRestartHandler struct {
	ops *service.SeedRestartService
}

func NewSeedRestartHandler() *SeedRestartHandler {
	return &SeedRestartHandler{ops: service.NewSeedRestartService()}
}

// PreviewRestart 预览重建计划：展示将被删除的计划与批次，返回一次性 token。
// POST /api/seeds/:id/restart-preview
func (h *SeedRestartHandler) PreviewRestart(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法种子 ID")
		return
	}
	var body struct {
		IntervalHours int            `json:"interval_hours"`
		Budget        map[string]any `json:"budget"`
	}
	if err := c.ShouldBindJSON(&body); err != nil && !errors.Is(err, io.EOF) {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.ops.Preview(c.Request.Context(), id, body.IntervalHours, body.Budget)
	if err != nil {
		if errors.Is(err, service.ErrSeedRestartInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "种子不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, res)
}

// Restart 用预览 token 重建计划。
// POST /api/seeds/:id/restart
func (h *SeedRestartHandler) Restart(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法种子 ID")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	plan, counts, err := h.ops.Restart(c.Request.Context(), id, body.Token, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrSeedRestartInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "种子不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "计划已重建", gin.H{"plan": plan, "deleted": counts})
}

// Options 项目下拉选项。GET /api/projects/options
func (h *ProjectOpsHandler) Options(c *gin.Context) {
	items, err := h.ops.Options(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// Stats 项目/资产规模总览。GET /api/projects/stats
func (h *ProjectOpsHandler) Stats(c *gin.Context) {
	st, err := h.ops.Stats(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, st)
}

// CycleStatus 调度侧健康快照。GET /api/project-cycle/status
func (h *ProjectOpsHandler) CycleStatus(c *gin.Context) {
	st, err := h.ops.CycleStatus(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, st)
}

// UploadIcon 上传项目图标（原始字节，Content-Type 为 image/png|jpeg|webp）。
// PUT /api/projects/:id/icon
func (h *ProjectOpsHandler) UploadIcon(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, service.ProjectIconMaxBytes+1)
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		utils.BadRequest(c, "读取图标失败: "+err.Error())
		return
	}
	p, err := h.ops.SetIcon(c.Request.Context(), id, data, c.GetHeader("Content-Type"))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrProjectInput):
			utils.BadRequest(c, err.Error())
		case errors.Is(err, repo.ErrNotFound):
			utils.NotFound(c, "项目不存在")
		default:
			utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		}
		return
	}
	utils.SuccessWithMessage(c, "图标已更新", p)
}

// DeleteIcon 清空项目图标。DELETE /api/projects/:id/icon
func (h *ProjectOpsHandler) DeleteIcon(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	p, err := h.ops.ClearIcon(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "项目不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "图标已清除", p)
}
