package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxBodyLimit 给请求体套 http.MaxBytesReader 上限，防止未设限的 JSON 端点
// 被超大 body 撑爆内存。默认 32MiB；个别上传端点（MCP 4MiB / 图标 / 本地文档）
// 已有自己的更小限制，不受影响。
func MaxBodyLimit(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}
