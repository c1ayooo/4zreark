package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// allowedOrigins 是允许的 Origin 全等白名单；ZRE_CORS_ORIGINS（逗号分隔）可追加。
func allowedOrigins() []string {
	origins := []string{
		"http://localhost:5173",
		"http://localhost:3000",
		"http://127.0.0.1:5173",
		"http://127.0.0.1:3000",
	}
	if extra := os.Getenv("ZRE_CORS_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
	}
	return origins
}

// OriginAllowed 报告 Origin 是否在白名单里（全等比较）。
// 除 CORS 中间件外，WebSocket 升级校验也用它，两处口径一致。
func OriginAllowed(origin string) bool {
	for _, allowed := range allowedOrigins() {
		if origin == allowed {
			return true
		}
	}
	return false
}

// CORSMiddleware handles CORS。
// 白名单用全等比较：前缀匹配会被 http://localhost:5173.evil.com 这类域名绕过。
// 额外来源用 ZRE_CORS_ORIGINS（逗号分隔）注入，例如前端部署在独立域名时。
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		if OriginAllowed(origin) || origin == "" {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
