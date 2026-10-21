package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/repo"
)

func TestMCPInitializeNegotiatesProtocol(t *testing.T) {
	s := NewMCPService()
	key := &repo.APIKey{ID: 1}
	req := &RPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
	}
	resp, err := s.Handle(context.Background(), req, key)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	m, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("initialize 结果类型不对: %T", resp.Result)
	}
	if m["protocolVersion"] != "2025-03-26" {
		t.Fatalf("应回显客户端支持的版本，实际 %v", m["protocolVersion"])
	}
	if string(resp.ID) != "1" {
		t.Fatalf("ID 未透传: %s", resp.ID)
	}

	// 不认识的版本回落到服务端最新版本。
	req.Params = json.RawMessage(`{"protocolVersion":"1999-01-01"}`)
	resp, _ = s.Handle(context.Background(), req, key)
	if resp.Result.(map[string]any)["protocolVersion"] != mcpProtocolVersions[0] {
		t.Fatalf("未知版本应回落到 %s", mcpProtocolVersions[0])
	}
}

func TestMCPToolsListIsWellFormed(t *testing.T) {
	s := NewMCPService()
	resp, err := s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"abc"`),
		Method:  "tools/list",
	}, &repo.APIKey{ID: 1, Scopes: []string{ScopeAssetsRead}})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	result := resp.Result.(map[string]any)
	tools, _ := result["tools"].([]mcpTool)
	reg := s.toolRegistry()
	if len(tools) != len(reg) {
		t.Fatalf("tools/list 数量 %d 与注册表 %d 不一致", len(tools), len(reg))
	}
	if len(tools) < 60 {
		t.Fatalf("工具数量 = %d，扩展后应覆盖 60+", len(tools))
	}

	names := make(map[string]bool, len(reg))
	for _, h := range reg {
		if h.Tool.Name == "" {
			t.Fatal("存在空工具名")
		}
		if names[h.Tool.Name] {
			t.Fatalf("工具名重复: %s", h.Tool.Name)
		}
		names[h.Tool.Name] = true
		if len(h.Scopes) == 0 && len(h.AnyScopes) == 0 {
			t.Fatalf("工具 %s 没有声明 scope", h.Tool.Name)
		}
		if h.Run == nil {
			t.Fatalf("工具 %s 没有实现", h.Tool.Name)
		}
		for _, sc := range h.Scopes {
			if !scopeSet[sc] {
				t.Fatalf("工具 %s 声明了未知 scope %s", h.Tool.Name, sc)
			}
		}
		for _, sc := range h.AnyScopes {
			if !scopeSet[sc] {
				t.Fatalf("工具 %s 声明了未知 scope %s", h.Tool.Name, sc)
			}
		}
		if h.Tool.Annotations == nil {
			t.Fatalf("工具 %s 缺少 annotations", h.Tool.Name)
		}
		if h.Tool.InputSchema["type"] != "object" {
			t.Fatalf("工具 %s 的 inputSchema 必须是 object", h.Tool.Name)
		}
	}

	for _, want := range []string{
		"list_assets", "create_project", "create_seed", "list_plans", "execute_run",
		"create_task", "start_task", "get_task_results", "scan_ports", "scan_subdomains",
		"scan_fingerprint", "scan_vulns", "scan_nuclei", "list_vulnerabilities", "list_pocs",
	} {
		if !names[want] {
			t.Fatalf("缺少工具: %s", want)
		}
	}
}

func TestMCPUnknownMethodAndNotification(t *testing.T) {
	s := NewMCPService()
	key := &repo.APIKey{ID: 1}

	resp, err := s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "resources/list",
	}, key)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("未知方法应返回 -32601，实际 %+v", resp.Error)
	}

	resp, err = s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}, key)
	if err != nil || resp != nil {
		t.Fatalf("通知不应产生响应: resp=%v err=%v", resp, err)
	}
}

func TestResolveKeyProject(t *testing.T) {
	bound := int64(7)
	key := &repo.APIKey{ID: 1, ProjectID: &bound}

	got, err := resolveKeyProject(key, nil)
	if err != nil || got != 7 {
		t.Fatalf("绑定 key 缺省应返回 7，实际 %d/%v", got, err)
	}
	other := int64(8)
	if _, err := resolveKeyProject(key, &other); err == nil {
		t.Fatal("绑定 key 访问其它项目应报错")
	}
	if _, err := resolveKeyProject(key, &bound); err != nil {
		t.Fatalf("绑定 key 访问自身项目应放行: %v", err)
	}

	global := &repo.APIKey{ID: 2}
	if _, err := resolveKeyProject(global, nil); err == nil {
		t.Fatal("未绑定 key 缺省应要求 project_id")
	}
	if got, err := resolveKeyProject(global, &other); err != nil || got != 8 {
		t.Fatalf("未绑定 key 应放行显式项目，实际 %d/%v", got, err)
	}
}

func TestMCPToolCallRejectsUnknownTool(t *testing.T) {
	s := NewMCPService()
	resp, err := s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("3"),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"drop_database","arguments":{}}`),
	}, &repo.APIKey{ID: 1, Scopes: []string{ScopeAssetsRead}})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	res, ok := resp.Result.(*mcpToolResult)
	if !ok || !res.IsError {
		t.Fatalf("未知工具应返回 isError，实际 %#v", resp.Result)
	}
}

func TestValidateScopes(t *testing.T) {
	got, err := ValidateScopes(nil)
	if err != nil || len(got) != 1 || got[0] != ScopeAssetsRead {
		t.Fatalf("空 scopes 应回落到 assets:read，实际 %v/%v", got, err)
	}
	got, err = ValidateScopes([]string{" tasks:read ", "tasks:read", "assets:read"})
	if err != nil || len(got) != 2 || got[0] != "tasks:read" {
		t.Fatalf("去重/trim 结果不对: %v/%v", got, err)
	}
	if _, err := ValidateScopes([]string{"root"}); err == nil {
		t.Fatal("未知 scope 应报错")
	}
	if len(AllScopes()) != len(ScopeCatalog) {
		t.Fatal("AllScopes 与 ScopeCatalog 数量不一致")
	}
}

func TestMCPToolScopeEnforcement(t *testing.T) {
	s := NewMCPService()
	key := &repo.APIKey{ID: 1, Scopes: []string{ScopeAssetsRead}}

	call := func(name string, args map[string]any) *mcpToolResult {
		params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
		resp, err := s.Handle(context.Background(), &RPCRequest{
			JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params,
		}, key)
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		return resp.Result.(*mcpToolResult)
	}

	if res := call("create_project", map[string]any{}); !res.IsError || !strings.Contains(res.Content[0].Text, ScopeProjectsWrite) {
		t.Fatalf("缺少 projects:write 时应拒绝，实际 %+v", res)
	}
	if res := call("scan_ports", map[string]any{"target": "127.0.0.1"}); !res.IsError || !strings.Contains(res.Content[0].Text, ScopeScansRun) {
		t.Fatalf("缺少 scans:run 时应拒绝，实际 %+v", res)
	}
	if res := call("list_vulnerabilities", map[string]any{}); !res.IsError || !strings.Contains(res.Content[0].Text, ScopeVulnsRead) {
		t.Fatalf("缺少 vulns:read 时应拒绝，实际 %+v", res)
	}

	// 有权限但绑定了项目：漏洞工具仍应拒绝。
	bound := int64(1)
	key.ProjectID = &bound
	key.Scopes = []string{ScopeVulnsRead}
	if res := call("list_vulnerabilities", map[string]any{}); !res.IsError || !strings.Contains(res.Content[0].Text, "全部项目") {
		t.Fatalf("绑定项目的 key 调漏洞工具应拒绝，实际 %+v", res)
	}
}
