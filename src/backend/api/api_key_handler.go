package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// APIKeyHandler 管理外部平台 / MCP 的只读访问凭证。
// 创建响应里的完整 key 只出现一次，列表接口永远只返回前缀。
type APIKeyHandler struct {
	keys *service.APIKeyService
}

func NewAPIKeyHandler() *APIKeyHandler {
	return &APIKeyHandler{keys: service.NewAPIKeyService()}
}

// ListAPIKeys GET /api/api-keys
func (h *APIKeyHandler) ListAPIKeys(c *gin.Context) {
	items, err := h.keys.List(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// CreateAPIKey POST /api/api-keys
func (h *APIKeyHandler) CreateAPIKey(c *gin.Context) {
	var body service.APIKeyInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	createdBy, _ := c.Get("user_id")
	uid, _ := createdBy.(string)
	created, err := h.keys.Create(c.Request.Context(), body, uid)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "API key 已创建，明文只显示这一次", created)
}

// UpdateAPIKey PUT /api/api-keys/:id
// 目前只支持启停，吊销用 DELETE。
func (h *APIKeyHandler) UpdateAPIKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法凭证 ID")
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if body.Enabled == nil {
		utils.BadRequest(c, "需要 enabled 字段")
		return
	}
	if err := h.keys.SetEnabled(c.Request.Context(), id, *body.Enabled); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "凭证不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "凭证状态已更新", gin.H{"id": id, "enabled": *body.Enabled})
}

// DeleteAPIKey DELETE /api/api-keys/:id
func (h *APIKeyHandler) DeleteAPIKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法凭证 ID")
		return
	}
	if err := h.keys.Delete(c.Request.Context(), id); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "凭证不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "凭证已删除", gin.H{"id": id})
}
