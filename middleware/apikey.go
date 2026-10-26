package middleware

import (
	"errors"
	"strings"

	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

var apiKeyService = service.NewAPIKeyService()

// APIKeyMiddleware 是外部平台 / MCP 的鉴权入口，和 JWT 登录态完全分开：
// 只认 Bearer <api-key> 或 X-API-Key，不接受 JWT。
func APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := ExtractAPIKey(c)
		if raw == "" {
			c.Header("WWW-Authenticate", `Bearer realm="4zreark-mcp"`)
			utils.Unauthorized(c, "缺少 API key")
			c.Abort()
			return
		}

		key, err := apiKeyService.Authenticate(c.Request.Context(), raw)
		if err != nil {
			c.Header("WWW-Authenticate", `Bearer realm="4zreark-mcp", error="invalid_token"`)
			msg := "API key 无效"
			switch {
			case errors.Is(err, service.ErrAPIKeyDisabled):
				msg = "API key 已禁用"
			case errors.Is(err, service.ErrAPIKeyExpired):
				msg = "API key 已过期"
			}
			utils.Unauthorized(c, msg)
			c.Abort()
			return
		}

		c.Set("api_key", key)
		c.Set("api_key_id", key.ID)
		c.Set("api_key_project_id", key.ProjectID)
		c.Set("api_key_scopes", key.Scopes)
		c.Next()
	}
}

// ExtractAPIKey 兼容两种常见写法：
//   - Authorization: Bearer zr_xxx（Claude Code / Cursor 等 MCP 客户端默认）
//   - X-API-Key: zr_xxx（网关和脚本更顺手）
func ExtractAPIKey(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader("X-API-Key")); v != "" {
		return v
	}
	parts := strings.Fields(c.GetHeader("Authorization"))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
