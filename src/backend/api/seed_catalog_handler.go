package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// SeedCatalogHandler 提供种子能力说明与覆盖统计。
type SeedCatalogHandler struct {
	svc *service.SeedCatalogService
}

func NewSeedCatalogHandler() *SeedCatalogHandler {
	return &SeedCatalogHandler{svc: service.NewSeedCatalogService()}
}

// Capabilities GET /api/seeds/capabilities
func (h *SeedCatalogHandler) Capabilities(c *gin.Context) {
	utils.Success(c, h.svc.Capabilities())
}

// DomainCounts GET /api/seeds/domain-counts?project_id=
func (h *SeedCatalogHandler) DomainCounts(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	items, err := h.svc.DomainCounts(c.Request.Context(), projectID)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// CreateBatch POST /api/seeds/batch
func (h *SeedCatalogHandler) CreateBatch(c *gin.Context) {
	var body service.SeedBatchRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	res, err := h.svc.CreateBatch(c.Request.Context(), body, name, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrSeedValidation) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "批量创建完成", res)
}
