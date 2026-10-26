package api

import (
	"errors"
	"io"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// FingerprintUpstreamHandler 触发一次指纹上游同步。
// 调度器在 main 启动后每 24 小时自动跑；这个入口用于运维手动补一轮。
type FingerprintUpstreamHandler struct {
	svc *service.FingerprintUpstreamService
}

func NewFingerprintUpstreamHandler() *FingerprintUpstreamHandler {
	return &FingerprintUpstreamHandler{svc: service.NewFingerprintUpstreamService()}
}

// Sync 同步 wappalyzergo / webanalyze / dddd。
// POST /api/governance/fingerprints/sync-upstream  {"force": false}
func (h *FingerprintUpstreamHandler) Sync(c *gin.Context) {
	var body struct {
		Force bool `json:"force"`
	}
	if err := c.ShouldBindJSON(&body); err != nil && !errors.Is(err, io.EOF) {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	outcomes, err := h.svc.SyncUpstream(c.Request.Context(), body.Force)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"sources": outcomes})
}
