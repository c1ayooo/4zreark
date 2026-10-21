package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// SourceHandler 数据源与凭据（G4）。凭据只写不读。
type SourceHandler struct {
	sources *service.SourceService
}

func NewSourceHandler() *SourceHandler {
	return &SourceHandler{sources: service.NewSourceService()}
}

// ListSources GET /api/sources
func (h *SourceHandler) ListSources(c *gin.Context) {
	items, err := h.sources.List(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// GetSource GET /api/sources/:id
func (h *SourceHandler) GetSource(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法数据源 ID")
		return
	}
	src, err := h.sources.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "数据源不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, src)
}

// CreateSource POST /api/sources
func (h *SourceHandler) CreateSource(c *gin.Context) {
	var body service.SourceInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	src, err := h.sources.Create(c.Request.Context(), body)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "数据源已创建", src)
}

// UpdateSource PUT /api/sources/:id
func (h *SourceHandler) UpdateSource(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法数据源 ID")
		return
	}
	var body service.SourceInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	src, err := h.sources.Update(c.Request.Context(), id, body)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "数据源不存在")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "数据源已更新", src)
}

// DeleteSource DELETE /api/sources/:id
func (h *SourceHandler) DeleteSource(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法数据源 ID")
		return
	}
	if err := h.sources.Delete(c.Request.Context(), id); err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// GetLegacyConfig 兼容旧设置页 GET /api/thirdparty/config。
// 底层读 sources 表 + 全局配置，key 脱敏返回。
func (h *SourceHandler) GetLegacyConfig(c *gin.Context) {
	cfg, sources, err := h.sources.LegacyConfig(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"config": cfg, "configured_sources": sources})
}

// UpdateLegacyConfig 兼容旧设置页 PUT /api/thirdparty/config。
// 写入 sources 表（AES-GCM 密文），不再使用旧的第三方客户端。
func (h *SourceHandler) UpdateLegacyConfig(c *gin.Context) {
	var body map[string]string
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	sources, err := h.sources.UpdateLegacy(c.Request.Context(), body)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, gin.H{"message": "配置已更新", "configured_sources": sources})
}

// GetLegacySources 兼容旧设置页 GET /api/thirdparty/sources。
func (h *SourceHandler) GetLegacySources(c *gin.Context) {
	_, sources, err := h.sources.LegacyConfig(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"sources": sources})
}

// TestSource POST /api/sources/:id/test
func (h *SourceHandler) TestSource(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法数据源 ID")
		return
	}
	res, err := h.sources.Test(c.Request.Context(), id)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if res.OK {
		utils.SuccessWithMessage(c, res.Message, res)
		return
	}
	utils.Error(c, utils.ErrCodeInternalError, res.Message)
}
