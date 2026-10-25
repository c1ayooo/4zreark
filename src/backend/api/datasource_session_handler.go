package api

import (
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// DatasourceSessionHandler 数据源会话托管：清单/维护（管理员）。
// 扫码登录的 begin/poll/cancel 见 qr_session_handler。
type DatasourceSessionHandler struct{}

func NewDatasourceSessionHandler() *DatasourceSessionHandler {
	return &DatasourceSessionHandler{}
}

// List GET /api/datasource-sessions
func (h *DatasourceSessionHandler) List(c *gin.Context) {
	items, err := service.ListDatasourceSessions(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items})
}

// Save PUT /api/datasource-sessions/:provider
func (h *DatasourceSessionHandler) Save(c *gin.Context) {
	var body service.DatasourceSessionSaveInput
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	provider := c.Param("provider")
	if err := service.SaveDatasourceSession(c.Request.Context(), provider, body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "会话已保存", nil)
}

// Delete DELETE /api/datasource-sessions/:provider
func (h *DatasourceSessionHandler) Delete(c *gin.Context) {
	provider := c.Param("provider")
	if err := service.DeleteDatasourceSession(c.Request.Context(), provider); err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "会话已清除", nil)
}
