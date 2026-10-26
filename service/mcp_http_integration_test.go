package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/api"
	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/middleware"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/gin-gonic/gin"
)

// TestMCPHTTPIntegration 是可跳过的端到端冒烟：
// 直连真实库，走管理接口创建 API key，再走 HTTP 中间件 + MCP handler，
// 覆盖资产读取、项目/治理/任务写操作、扫描目标边界、漏洞/POC 的全项目限制。
//
//	ZRE_MCP_IT=1 ZRE_PG_PASSWORD=$(cat ../../.pgpass.local) \
//	  go test ./service -run TestMCPHTTPIntegration -v
func TestMCPHTTPIntegration(t *testing.T) {
	if os.Getenv("ZRE_MCP_IT") != "1" {
		t.Skip("设置 ZRE_MCP_IT=1 并导出 ZRE_PG_PASSWORD 后运行")
	}
	password := os.Getenv("ZRE_PG_PASSWORD")
	if password == "" {
		t.Fatal("ZRE_PG_PASSWORD 为空")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := repo.Open(ctx, &config.PostgresConfig{
		Host: "127.0.0.1", Port: 25433, User: "zre", Password: password,
		DBName: "zreark", Schema: "zre", SSLMode: "disable", MaxConns: 2, MinConns: 1,
	})
	if err != nil {
		t.Fatalf("连接数据库失败: %v", err)
	}
	defer repo.Default().Close()

	var projectID int64
	if err := repo.Default().Pool().QueryRow(ctx,
		`SELECT id FROM projects ORDER BY id LIMIT 1`).Scan(&projectID); err != nil {
		t.Skipf("库里没有项目，跳过: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	mcpHandler := api.NewMCPHandler()
	keyHandler := api.NewAPIKeyHandler()
	r.POST("/api/mcp", middleware.APIKeyMiddleware(), mcpHandler.Serve)

	admin := r.Group("/api-keys")
	admin.Use(func(c *gin.Context) {
		c.Set("user_id", "integration-test")
		c.Set("role", "admin")
		c.Next()
	}, middleware.AdminMiddleware())
	admin.GET("", keyHandler.ListAPIKeys)
	admin.POST("", keyHandler.CreateAPIKey)
	admin.PUT("/:id", keyHandler.UpdateAPIKey)
	admin.DELETE("/:id", keyHandler.DeleteAPIKey)

	do := func(method, path string, payload any, token string) (int, map[string]any) {
		var body *bytes.Reader
		if payload == nil {
			body = bytes.NewReader(nil)
		} else {
			b, _ := json.Marshal(payload)
			body = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	rpc := func(token string, id int, method string, params any) (int, map[string]any) {
		return do(http.MethodPost, "/api/mcp", map[string]any{
			"jsonrpc": "2.0", "id": id, "method": method, "params": params,
		}, token)
	}
	call := func(token string, id int, name string, args map[string]any) (bool, string, map[string]any) {
		code, out := rpc(token, id, "tools/call", map[string]any{"name": name, "arguments": args})
		if code != http.StatusOK {
			return true, fmt.Sprintf("HTTP %d: %v", code, out), nil
		}
		res, _ := out["result"].(map[string]any)
		isErr, _ := res["isError"].(bool)
		text := ""
		if content, _ := res["content"].([]any); len(content) > 0 {
			if c0, _ := content[0].(map[string]any); c0 != nil {
				text, _ = c0["text"].(string)
			}
		}
		sc, _ := res["structuredContent"].(map[string]any)
		return isErr, text, sc
	}

	createKey := func(name string, project *int64, scopes []string) (int64, string) {
		payload := map[string]any{"name": name, "scopes": scopes}
		if project != nil {
			payload["project_id"] = *project
		}
		code, out := do(http.MethodPost, "/api-keys", payload, "")
		if code != http.StatusOK {
			t.Fatalf("创建 key %s 失败: %d %v", name, code, out)
		}
		created, _ := out["data"].(map[string]any)
		rawKey, _ := created["key"].(string)
		idFloat, _ := created["id"].(float64)
		if rawKey == "" || idFloat == 0 {
			t.Fatalf("创建响应缺少 key/id: %v", created)
		}
		return int64(idFloat), rawKey
	}

	// 1) 未带 key 的 MCP 请求必须 401。
	if code, _ := rpc("", 1, "ping", nil); code != http.StatusUnauthorized {
		t.Fatalf("无 key 应 401，实际 %d", code)
	}

	// 2) 两把 key：全项目运维 key + 绑定项目只读 key。
	globalKeyID, globalKey := createKey("mcp-it-global", nil, []string{
		"assets:read", "projects:read", "projects:write",
		"governance:read", "governance:write", "tasks:read", "tasks:write",
		"scans:run", "vulns:read", "pocs:read",
	})
	defer func() { _, _ = do(http.MethodDelete, "/api-keys/"+strconv.FormatInt(globalKeyID, 10), nil, "") }()
	boundKeyID, boundKey := createKey("mcp-it-bound", &projectID, []string{"assets:read", "vulns:read", "scans:run"})
	defer func() { _, _ = do(http.MethodDelete, "/api-keys/"+strconv.FormatInt(boundKeyID, 10), nil, "") }()

	// 列表不返回明文。
	code, out := do(http.MethodGet, "/api-keys", nil, "")
	if code != http.StatusOK {
		t.Fatalf("列表失败: %d %v", code, out)
	}
	items, _ := out["data"].(map[string]any)["items"].([]any)
	for _, item := range items {
		m, _ := item.(map[string]any)
		if _, leaked := m["key"]; leaked {
			t.Fatal("列表不应返回完整 key")
		}
	}

	// 3) 绑定 key：资产读取、工具清单、scope 拒绝、全项目工具拒绝、扫描目标边界。
	code, out = rpc(boundKey, 1, "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	if code != http.StatusOK {
		t.Fatalf("initialize 失败: %d %v", code, out)
	}
	code, out = rpc(boundKey, 2, "tools/list", nil)
	if code != http.StatusOK {
		t.Fatalf("tools/list 失败: %d %v", code, out)
	}
	tools, _ := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) < 60 {
		t.Fatalf("工具数量 = %d，期望 60+", len(tools))
	}

	if isErr, text, _ := call(boundKey, 3, "list_assets", map[string]any{"page_size": 2}); isErr {
		t.Fatalf("list_assets 失败: %s", text)
	}
	var siteID int64
	if err := repo.Default().Pool().QueryRow(ctx,
		`SELECT id FROM sites WHERE project_id = $1 ORDER BY id LIMIT 1`, projectID).Scan(&siteID); err == nil {
		if isErr, text, _ := call(boundKey, 4, "get_asset", map[string]any{"site_id": siteID}); isErr {
			t.Fatalf("get_asset 失败: %s", text)
		}
	}
	if isErr, text, _ := call(boundKey, 5, "create_project", map[string]any{"code": "x", "name": "x"}); !isErr || !strings.Contains(text, "projects:write") {
		t.Fatalf("只读 key 建项目应被 scope 拒绝，实际 isErr=%v text=%s", isErr, text)
	}
	if isErr, text, _ := call(boundKey, 6, "list_vulnerabilities", map[string]any{}); !isErr || !strings.Contains(text, "全部项目") {
		t.Fatalf("绑定 key 调漏洞工具应被拒绝，实际 isErr=%v text=%s", isErr, text)
	}
	// 目标不在项目资产/种子范围内时，扫描应在发请求前被拦截。
	if isErr, text, _ := call(boundKey, 7, "scan_ports", map[string]any{
		"target": fmt.Sprintf("mcp-it-%d.invalid", time.Now().UnixNano()),
	}); !isErr || !strings.Contains(text, "不在该项目的资产/种子范围内") {
		t.Fatalf("越界扫描目标应被拒绝，实际 isErr=%v text=%s", isErr, text)
	}

	// 4) 停用即时生效。
	code, out = do(http.MethodPut, "/api-keys/"+strconv.FormatInt(boundKeyID, 10), map[string]any{"enabled": false}, "")
	if code != http.StatusOK {
		t.Fatalf("停用失败: %d %v", code, out)
	}
	if code, _ := rpc(boundKey, 8, "ping", nil); code != http.StatusUnauthorized {
		t.Fatalf("停用后应 401，实际 %d", code)
	}
	if code, out = do(http.MethodPut, "/api-keys/"+strconv.FormatInt(boundKeyID, 10), map[string]any{"enabled": true}, ""); code != http.StatusOK {
		t.Fatalf("启用失败: %d %v", code, out)
	}

	// 5) 全项目 key：项目 CRUD 与采集状态。
	stamp := time.Now().UnixNano()
	projectCode := fmt.Sprintf("mcpit%d", stamp)
	projectName := fmt.Sprintf("MCP IT %d", stamp)
	isErr, text, sc := call(globalKey, 10, "create_project", map[string]any{
		"code": projectCode, "name": projectName, "region": "domestic",
	})
	if isErr {
		t.Fatalf("create_project 失败: %s", text)
	}
	newProjectID := int64(sc["id"].(float64))
	defer func() {
		if newProjectID > 0 {
			_, _, _ = call(globalKey, 999, "delete_project", map[string]any{
				"project_id": newProjectID, "confirm_code": projectCode,
			})
		}
	}()
	if isErr, text, _ := call(globalKey, 11, "update_project", map[string]any{
		"project_id": newProjectID, "description": "integration test",
	}); isErr {
		t.Fatalf("update_project 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 12, "pause_project", map[string]any{
		"project_id": newProjectID, "reason": "it",
	}); isErr {
		t.Fatalf("pause_project 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 13, "resume_project", map[string]any{
		"project_id": newProjectID,
	}); isErr {
		t.Fatalf("resume_project 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 14, "get_project_collection_state", map[string]any{
		"project_id": newProjectID,
	}); isErr {
		t.Fatalf("get_project_collection_state 失败: %s", text)
	}

	// 6) 治理：种子 → 计划 → 批次。
	seedValue := fmt.Sprintf("mcp-it-%d.invalid", stamp)
	isErr, text, seedSC := call(globalKey, 20, "create_seed", map[string]any{
		"project_id": newProjectID, "kind": "domain", "value": seedValue,
	})
	if isErr {
		t.Fatalf("create_seed 失败: %s", text)
	}
	seedID := int64(seedSC["id"].(float64))
	isErr, text, planSC := call(globalKey, 21, "create_plan", map[string]any{
		"seed_id": seedID, "interval_hours": 24,
	})
	if isErr {
		t.Fatalf("create_plan 失败: %s", text)
	}
	planID := int64(planSC["id"].(float64))
	if isErr, text, _ := call(globalKey, 22, "update_plan", map[string]any{
		"plan_id": planID, "interval_hours": 48,
	}); isErr {
		t.Fatalf("update_plan 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 23, "list_seeds", map[string]any{"project_id": newProjectID}); isErr {
		t.Fatalf("list_seeds 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 24, "list_plans", map[string]any{"project_id": newProjectID}); isErr {
		t.Fatalf("list_plans 失败: %s", text)
	}
	// 触发批次：空域名种子也应能建出批次；失败则只记录不阻断其它断言。
	if isErr, text, _ := call(globalKey, 25, "trigger_plan", map[string]any{"plan_id": planID}); isErr {
		t.Logf("trigger_plan 返回工具错误（允许）: %s", text)
	}
	if isErr, text, _ := call(globalKey, 26, "list_runs", map[string]any{"project_id": newProjectID}); isErr {
		t.Fatalf("list_runs 失败: %s", text)
	}

	// 7) 任务：创建（不启动）→ 读取 → 删除。
	isErr, text, taskSC := call(globalKey, 30, "create_task", map[string]any{
		"project_id": newProjectID, "name": "mcp-it-task", "type": "port_scan",
		"targets": []string{"127.0.0.1"}, "target_type": "ip",
	})
	if isErr {
		t.Fatalf("create_task 失败: %s", text)
	}
	taskID, _ := taskSC["id"].(string)
	if taskID == "" {
		t.Fatalf("create_task 未返回 id: %v", taskSC)
	}
	defer func() {
		_, _, _ = call(globalKey, 998, "delete_task", map[string]any{"task_id": taskID})
	}()
	if isErr, text, _ := call(globalKey, 31, "get_task", map[string]any{"task_id": taskID}); isErr {
		t.Fatalf("get_task 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 32, "list_tasks", map[string]any{"project_id": newProjectID, "page_size": 5}); isErr {
		t.Fatalf("list_tasks 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 33, "get_task_logs", map[string]any{"task_id": taskID}); isErr {
		t.Fatalf("get_task_logs 失败: %s", text)
	}

	// 8) 漏洞/POC 读取：全项目 key 可以访问。
	if isErr, text, _ := call(globalKey, 40, "list_vulnerabilities", map[string]any{"page_size": 1}); isErr {
		t.Fatalf("list_vulnerabilities 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 41, "list_pocs", map[string]any{"page_size": 1}); isErr {
		t.Fatalf("list_pocs 失败: %s", text)
	}

	// 9) 清理治理数据（项目删除也会级联，但显式删除更直观）。
	if isErr, text, _ := call(globalKey, 50, "delete_plan", map[string]any{"plan_id": planID}); isErr {
		t.Fatalf("delete_plan 失败: %s", text)
	}
	if isErr, text, _ := call(globalKey, 51, "delete_seed", map[string]any{"seed_id": seedID}); isErr {
		t.Fatalf("delete_seed 失败: %s", text)
	}
}
