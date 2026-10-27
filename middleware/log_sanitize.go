package middleware

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// 安全审计 M8：访问日志不再携带完整令牌。
// WebSocket 的 JWT 走查询参数（gin 默认 Logger 会把整个 RawQuery 写进日志），
// API Key / 节点 token 等凭据也可能出现在敏感端点的 query 里。
// 统一在日志 formatter 出口把凭据类参数值打码；反代侧日志需另行配置。

var sensitiveQueryRe = regexp.MustCompile(`(?i)((?:^|&)(?:token|access_token|refresh_token|key|secret|password|code)=)[^&\s]+`)

// SanitizeQuery 把 query 串里凭据参数的值替换为 [REDACTED]。
func SanitizeQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	return sensitiveQueryRe.ReplaceAllString(rawQuery, "${1}[REDACTED]")
}

// SanitizedLogger 是脱敏版的 gin 访问日志（替代 gin.Default() 的 Logger）：
// 路径与查询串分开处理，凭据参数值不落日志。
func SanitizedLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(p gin.LogFormatterParams) string {
		path := p.Path
		if idx := strings.IndexByte(path, '?'); idx >= 0 {
			path = path[:idx] + "?" + SanitizeQuery(path[idx+1:])
		}
		return fmt.Sprintf("[GIN] %s | %3d | %13v | %15s | %-7s %s\n",
			p.TimeStamp.Format("2006/01/02 - 15:04:05"),
			p.StatusCode, p.Latency, p.ClientIP, p.Method, path)
	})
}
