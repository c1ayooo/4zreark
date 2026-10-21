package api

import (
	"errors"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// FingerprintImportHandler 是指纹规则导入与批量启停入口。
// 同时挂在 /api/fingerprints/* 与 /api/governance/fingerprints/* 两组路径上，
// 前者对齐 ScopesHub 端点表，后者是治理域原有前缀。
type FingerprintImportHandler struct {
	imports *service.FingerprintImportService
}

func NewFingerprintImportHandler() *FingerprintImportHandler {
	return &FingerprintImportHandler{imports: service.NewFingerprintImportService()}
}

// PreviewImport 导入预览：返回可导入/冲突/无效三类计数与一次性 token。
// POST /api/fingerprints/import
func (h *FingerprintImportHandler) PreviewImport(c *gin.Context) {
	var body service.FpImportRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.imports.Preview(c.Request.Context(), body)
	if err != nil {
		if errors.Is(err, service.ErrFpImportInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, res)
}

// CommitImport 确认导入：消费预览 token。
// POST /api/fingerprints/import/commit
func (h *FingerprintImportHandler) CommitImport(c *gin.Context) {
	var body struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	res, err := h.imports.Commit(c.Request.Context(), body.Token, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrFpImportInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "导入完成", res)
}

// BulkToggle 批量启停规则，单次最多 500 条。
// POST /api/fingerprints/bulk
func (h *FingerprintImportHandler) BulkToggle(c *gin.Context) {
	var body struct {
		Names   []string `json:"names" binding:"required"`
		Enabled *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	res, err := h.imports.BulkToggle(c.Request.Context(), body.Names, enabled, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrFpImportInput) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, res)
}
