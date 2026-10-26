package api

import (
	"context"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// QrSessionHandler 平台内扫码登录（无头浏览器托管）：begin 出二维码、poll 轮询、cancel 取消。
// 登录成功后 Cookie 落 datasource_sessions（管理员，路由挂 datasource-sessions 组）。
type QrSessionHandler struct{}

func NewQrSessionHandler() *QrSessionHandler { return &QrSessionHandler{} }

type qrBeginBody struct {
	ProxyURL string `json:"proxy_url"`
}

// Begin POST /api/datasource-sessions/:provider/qr/begin
func (h *QrSessionHandler) Begin(c *gin.Context) {
	provider := c.Param("provider")
	if !enterprise.QRLoginSupported(provider) {
		utils.BadRequest(c, "数据源 "+provider+" 暂不支持扫码登录")
		return
	}
	var body qrBeginBody
	_ = c.ShouldBindJSON(&body) // body 可选
	res, err := enterprise.QRLogin.Begin(provider, body.ProxyURL)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "二维码已生成，请使用对应手机 APP 扫码确认", res)
}

// Poll GET /api/datasource-sessions/:provider/qr/poll?session_id=
// confirmed 时 Cookie 自动落库并置 active；waiting 时返回最新二维码
// （上游二维码会自动刷新，前端据此更新展示，避免扫到过期码）。
func (h *QrSessionHandler) Poll(c *gin.Context) {
	provider := c.Param("provider")
	sessionID := c.Query("session_id")
	if sessionID == "" {
		utils.BadRequest(c, "session_id 必填")
		return
	}
	status, cookie, qrImage, err := enterprise.QRLogin.Poll(provider, sessionID)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	res := gin.H{"status": status}
	if qrImage != "" {
		res["qr_image"] = qrImage
	}
	if status == "confirmed" {
		cookieStr := cookie
		if err := service.SaveDatasourceSession(c.Request.Context(), provider,
			service.DatasourceSessionSaveInput{Cookie: &cookieStr}); err != nil {
			utils.Error(c, utils.ErrCodeDatabaseError, "会话保存失败: "+err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		_ = service.TouchDatasourceSession(ctx, provider)
		res["message"] = "登录成功，会话已保存"
	}
	utils.Success(c, res)
}

// Cancel POST /api/datasource-sessions/:provider/qr/cancel
func (h *QrSessionHandler) Cancel(c *gin.Context) {
	provider := c.Param("provider")
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.SessionID == "" {
		utils.BadRequest(c, "session_id 必填")
		return
	}
	cancelled := enterprise.QRLogin.Cancel(provider, body.SessionID)
	utils.Success(c, gin.H{"cancelled": cancelled})
}
