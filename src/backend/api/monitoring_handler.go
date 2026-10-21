package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// MonitoringHandler 是监控预设与计划批量操作入口。
type MonitoringHandler struct {
	svc *service.MonitoringService
}

func NewMonitoringHandler() *MonitoringHandler {
	return &MonitoringHandler{svc: service.NewMonitoringService()}
}

// ListPresets GET /api/monitoring-presets
func (h *MonitoringHandler) ListPresets(c *gin.Context) {
	items, err := h.svc.ListPresets(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// DefaultPreset GET /api/monitoring-defaults
func (h *MonitoringHandler) DefaultPreset(c *gin.Context) {
	p, err := h.svc.DefaultPreset(c.Request.Context())
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.Success(c, gin.H{"preset": nil})
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"preset": p})
}

type presetBody struct {
	Name          string         `json:"name"`
	IntervalHours int            `json:"interval_hours"`
	Budget        map[string]any `json:"budget"`
	IsDefault     bool           `json:"is_default"`
}

func (b presetBody) input() repo.MonitoringPresetInput {
	return repo.MonitoringPresetInput{
		Name: b.Name, IntervalHours: b.IntervalHours, Budget: b.Budget, IsDefault: b.IsDefault,
	}
}

func (h *MonitoringHandler) CreatePreset(c *gin.Context) {
	var body presetBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	p, err := h.svc.CreatePreset(c.Request.Context(), body.input(), name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrMonitoringInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "预设已创建", p)
}

func (h *MonitoringHandler) UpdatePreset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法预设 ID")
		return
	}
	var body presetBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	p, err := h.svc.UpdatePreset(c.Request.Context(), id, body.input(), name, c.ClientIP())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrMonitoringInput):
			utils.BadRequest(c, err.Error())
		case errors.Is(err, repo.ErrNotFound):
			utils.NotFound(c, "预设不存在")
		default:
			utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		}
		return
	}
	utils.SuccessWithMessage(c, "预设已更新", p)
}

func (h *MonitoringHandler) DeletePreset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法预设 ID")
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	if err := h.svc.DeletePreset(c.Request.Context(), id, name, c.ClientIP()); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "预设不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "预设已删除", nil)
}

// PreviewBulk POST /api/monitoring-bulk/preview
func (h *MonitoringHandler) PreviewBulk(c *gin.Context) {
	var body service.PlanBulkRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.svc.PreviewBulk(c.Request.Context(), body)
	if err != nil {
		if errors.Is(err, service.ErrMonitoringInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, res)
}

// ApplyBulk POST /api/monitoring-bulk
func (h *MonitoringHandler) ApplyBulk(c *gin.Context) {
	var body service.PlanBulkRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	res, err := h.svc.ApplyBulk(c.Request.Context(), body, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrMonitoringInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "批量更新完成", res)
}
