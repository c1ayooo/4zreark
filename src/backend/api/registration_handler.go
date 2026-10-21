package api

import (
	"errors"
	"strconv"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// RegistrationHandler 注册码管理（管理员）。
type RegistrationHandler struct {
	svc *service.RegistrationService
}

func NewRegistrationHandler() *RegistrationHandler {
	return &RegistrationHandler{svc: service.NewRegistrationService()}
}

// List GET /api/registration-codes?limit=
func (h *RegistrationHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	items, err := h.svc.List(c.Request.Context(), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// Generate POST /api/registration-codes
func (h *RegistrationHandler) Generate(c *gin.Context) {
	var body struct {
		Count     int        `json:"count"`
		Role      string     `json:"role"`
		MaxUses   int        `json:"max_uses"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	codes, err := h.svc.Generate(c.Request.Context(), body.Count, body.Role,
		body.MaxUses, body.ExpiresAt, c.GetString("username"))
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "注册码已生成（明文只显示这一次）", gin.H{"codes": codes, "count": len(codes)})
}

// Delete DELETE /api/registration-codes/:code
func (h *RegistrationHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("code")); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "注册码不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", nil)
}

// BatchDelete POST /api/registration-codes/batch-delete
func (h *RegistrationHandler) BatchDelete(c *gin.Context) {
	var body struct {
		Codes []string `json:"codes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	n, err := h.svc.DeleteBatch(c.Request.Context(), body.Codes)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", gin.H{"deleted": n})
}
