package router

import (
	"testing"

	"github.com/c1ayooo/4zreark/config"

	"github.com/gin-gonic/gin"
)

// 路由表是外部接入的契约：MCP 端点与 API key 管理接口都不能被后续重构静默移除。
func TestMCPAndAPIKeyRoutesRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// 部分 handler 构造时读取全局配置；测试不连库，只加载 YAML。
	config.LoadConfig("../config/config.yaml")
	r := SetupRouter()

	routes := make(map[string]bool, len(r.Routes()))
	for _, route := range r.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	for _, want := range []string{
		"POST /api/mcp",
		"GET /api/mcp",
		"DELETE /api/mcp",
		"GET /api/api-keys",
		"POST /api/api-keys",
		"PUT /api/api-keys/:id",
		"DELETE /api/api-keys/:id",
	} {
		if !routes[want] {
			t.Errorf("缺少路由 %s", want)
		}
	}
}
