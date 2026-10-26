package api

import (
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// EnrichmentHandler 暴露情报富化总览。
type EnrichmentHandler struct {
	svc *service.EnrichmentStatusService
}

func NewEnrichmentHandler() *EnrichmentHandler {
	return &EnrichmentHandler{svc: service.NewEnrichmentStatusService()}
}

// Status GET /api/enrichment/status
func (h *EnrichmentHandler) Status(c *gin.Context) {
	st, err := h.svc.Status(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, st)
}
