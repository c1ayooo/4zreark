package api

import (
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// SystemUpdateHandler 平台自更新：检测 GitHub 更高版本、下载替换、进度轮询。
type SystemUpdateHandler struct{}

func NewSystemUpdateHandler() *SystemUpdateHandler { return &SystemUpdateHandler{} }

// Version GET /api/system/version — 当前版本 + GitHub 最新版（缓存 10 分钟）。
func (h *SystemUpdateHandler) Version(c *gin.Context) {
	utils.Success(c, service.CheckVersion(c.Request.Context()))
}

// UpdateStatus GET /api/system/update/status — 更新进度（前端轮询渲染进度条）。
func (h *SystemUpdateHandler) UpdateStatus(c *gin.Context) {
	utils.Success(c, service.GetUpdateState())
}

// StartUpdate POST /api/system/update — 启动自更新（幂等）。
func (h *SystemUpdateHandler) StartUpdate(c *gin.Context) {
	var body struct {
		Version string `json:"version"`
	}
	_ = c.ShouldBindJSON(&body)
	state, err := service.StartSelfUpdate(body.Version)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "更新已启动", state)
}
