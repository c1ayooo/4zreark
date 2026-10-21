package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// AuditHandler 审计日志查询。写入口在中间件与各域自动动作，这里只读。
type AuditHandler struct {
	audits *service.AuditService
}

func NewAuditHandler() *AuditHandler {
	return &AuditHandler{audits: service.NewAuditService()}
}

// ListAudit GET /api/audit?username=&action=&module=&status=&page=&page_size=
func (h *AuditHandler) ListAudit(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	var status *int
	if raw := c.Query("status"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && (v == 0 || v == 1) {
			status = &v
		}
	}

	logs, total, err := h.audits.List(c.Request.Context(), repo.AuditFilter{
		Username: c.Query("username"),
		Action:   c.Query("action"),
		Module:   c.Query("module"),
		Status:   status,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithPagination(c, logs, total, page, pageSize)
}
