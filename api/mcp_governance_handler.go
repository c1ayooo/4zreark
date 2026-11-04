package api

import (
	"errors"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// MCPGovernanceHandler 是 MCP 治理面的管理端（JWT 管理员，与 API key 分离）：
// 工具总闸的查看与启停、速率配额查看与调整。
type MCPGovernanceHandler struct {
	svc *service.MCPGovernanceService
}

func NewMCPGovernanceHandler() *MCPGovernanceHandler {
	return &MCPGovernanceHandler{svc: service.NewMCPGovernanceService()}
}

// Overview GET /api/mcp-governance
func (h *MCPGovernanceHandler) Overview(c *gin.Context) {
	tools, settings, err := h.svc.Overview(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"tools": tools, "rate_limit_per_min": settings.RateLimitPerMin})
}

// SetToolEnabled PUT /api/mcp-governance/tools/:name  body: {"enabled": bool}
func (h *MCPGovernanceHandler) SetToolEnabled(c *gin.Context) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enabled == nil {
		utils.BadRequest(c, "需要 enabled 字段")
		return
	}
	if err := h.svc.SetToolEnabled(c.Request.Context(), c.Param("name"), *body.Enabled); err != nil {
		if errors.Is(err, service.ErrMCPToolUnknown) {
			utils.NotFound(c, err.Error()+": "+c.Param("name"))
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "工具开关已更新", gin.H{"tool": c.Param("name"), "enabled": *body.Enabled})
}

// UpdateRateLimit PUT /api/mcp-governance/rate-limit  body: {"per_minute": 60}
func (h *MCPGovernanceHandler) UpdateRateLimit(c *gin.Context) {
	var body struct {
		PerMinute int `json:"per_minute"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	settings, err := h.svc.SaveSettings(c.Request.Context(), service.MCPGovernanceSettings{RateLimitPerMin: body.PerMinute})
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "速率配额已更新，立即生效", gin.H{"rate_limit_per_min": settings.RateLimitPerMin})
}
