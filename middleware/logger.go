package middleware

import (
	"context"
	"log"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/gin-gonic/gin"
)

// OperationLogMiddleware logs user operations
func OperationLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip logging for GET requests
		if c.Request.Method == "GET" {
			c.Next()
			return
		}

		startTime := time.Now()

		c.Next()

		// Get user info from context
		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")

		// Create operation log
		log := models.OperationLog{
			Action:    c.Request.Method,
			Module:    getModuleFromPath(c.Request.URL.Path),
			Target:    c.Request.URL.Path,
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Status:    getStatusFromCode(c.Writer.Status()),
			CreatedAt: startTime,
		}

		if userID != nil {
			objID, _ := oid.ObjectIDFromHex(userID.(string))
			log.UserID = objID
		}
		if username != nil {
			log.Username = username.(string)
		}
		// 外部平台 / MCP 走 API key，没有用户上下文；
		// 把 key 名记进审计，便于区分调用来源。
		if keyVal, ok := c.Get("api_key"); ok {
			if key, ok := keyVal.(*repo.APIKey); ok && key != nil {
				log.Username = "apikey:" + key.Name
			}
		}

		// Save log asynchronously
		go saveOperationLog(log)
	}
}

func saveOperationLog(entry models.OperationLog) {
	r := repo.Default()
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.Audits().Add(ctx, &entry); err != nil {
		log.Printf("[audit] 写操作日志失败: %v", err)
	}
}

func getModuleFromPath(path string) string {
	modules := map[string]string{
		"/api/auth":     "认证",
		"/api/user":     "用户管理",
		"/api/asset":    "资产管理",
		"/api/task":     "任务管理",
		"/api/vuln":     "漏洞管理",
		"/api/node":     "节点管理",
		"/api/plugin":   "插件管理",
		"/api/system":   "系统设置",
		"/api/mcp":      "MCP 接入",
		"/api/api-keys": "MCP 接入",
	}

	for prefix, module := range modules {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return module
		}
	}
	return "其他"
}

func getStatusFromCode(code int) int {
	if code >= 200 && code < 400 {
		return 1
	}
	return 0
}
