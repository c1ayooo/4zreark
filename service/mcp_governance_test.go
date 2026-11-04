package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/repo"
)

// stubGovernance 替换治理面入口，隔离 DB。
func stubGovernance(t *testing.T, switches map[string]bool, quota func(keyID int64) (int64, error)) {
	t.Helper()
	prev := mcpGovernance
	mcpGovernance = func() repo.MCPGovernanceRepo {
		return &fakeGovernance{switches: switches, quota: quota}
	}
	t.Cleanup(func() { mcpGovernance = prev })
}

type fakeGovernance struct {
	switches map[string]bool
	quota    func(keyID int64) (int64, error)
}

func (f *fakeGovernance) ToolEnabled(_ context.Context, tool string) (bool, error) {
	if v, ok := f.switches[tool]; ok {
		return v, nil
	}
	return true, nil
}

func (f *fakeGovernance) SetToolSwitch(_ context.Context, _ string, _ bool) error { return nil }

func (f *fakeGovernance) ListToolSwitches(_ context.Context) ([]repo.MCPSwitchState, error) {
	return nil, nil
}

func (f *fakeGovernance) ConsumeQuota(_ context.Context, keyID int64) (int64, error) {
	if f.quota == nil {
		return 1, nil
	}
	return f.quota(keyID)
}

// 只读 key（assets:read）的 tools/list 不应出现任何写/扫描类工具。
func TestMCPToolsListFilteredByScopes(t *testing.T) {
	s := NewMCPService()
	stubGovernance(t, nil, nil)
	key := &repo.APIKey{ID: 1, Scopes: []string{ScopeAssetsRead}}

	resp, err := s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/list",
	}, key)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	result := resp.Result.(map[string]any)
	raw, _ := json.Marshal(result["tools"])
	var tools []mcpTool
	if err := json.Unmarshal(raw, &tools); err != nil {
		t.Fatalf("解析 tools: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("只读 key 应至少看到资产读取工具")
	}
	for _, tool := range tools {
		for _, h := range s.toolRegistry() {
			if h.Tool.Name != tool.Name {
				continue
			}
			if !keyAllowsTool(key, h) {
				t.Fatalf("工具 %s 需要 %v / 任一 %v，不该出现在只读 key 的 tools/list", tool.Name, h.Scopes, h.AnyScopes)
			}
		}
	}
	// 写类工具必须被过滤：scan_vulns 要求 scans:run
	for _, tool := range tools {
		if tool.Name == "scan_vulns" {
			t.Fatal("只读 key 不应看到 scan_vulns")
		}
	}
}

// 全权限 key 能看到全部工具。
func TestMCPToolsListFullScopes(t *testing.T) {
	s := NewMCPService()
	stubGovernance(t, nil, nil)
	key := &repo.APIKey{ID: 1, Scopes: AllScopes()}

	resp, _ := s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/list",
	}, key)
	raw, _ := json.Marshal(resp.Result.(map[string]any)["tools"])
	var tools []mcpTool
	_ = json.Unmarshal(raw, &tools)
	if len(tools) != len(s.toolRegistry()) {
		t.Fatalf("全权限 key 应看到全部 %d 个工具，实际 %d 个", len(s.toolRegistry()), len(tools))
	}
}

// 总闸停用的工具从 tools/list 消失，tools/call 也被拒，且错误信息与权限缺失可区分。
func TestMCPToolSwitchGates(t *testing.T) {
	s := NewMCPService()
	stubGovernance(t, map[string]bool{"scan_ports": false}, nil)
	key := &repo.APIKey{ID: 1, Scopes: AllScopes()}

	resp, _ := s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/list",
	}, key)
	raw, _ := json.Marshal(resp.Result.(map[string]any)["tools"])
	if strings.Contains(string(raw), `"scan_ports"`) {
		t.Fatal("总闸停用的 scan_ports 不应出现在 tools/list")
	}

	resp, _ = s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "tools/call",
		Params: json.RawMessage(`{"name":"scan_ports","arguments":{}}`),
	}, key)
	// 工具级错误按 MCP 惯例落在 result.isError，不是 JSON-RPC error。
	result, _ := json.Marshal(resp.Result)
	var tr mcpToolResult
	if err := json.Unmarshal(result, &tr); err != nil || !tr.IsError {
		t.Fatalf("停用工具调用应返回 isError 结果，实际 %s", string(result))
	}
	if !strings.Contains(tr.Content[0].Text, "管理员停用") {
		t.Fatalf("错误信息应注明管理员停用，实际 %s", tr.Content[0].Text)
	}
}

// 速率配额：限额内放行，超出后返回 ErrMCPRateLimited 且带重试秒数。
// 无 DB 的单测里上限回落 MCPDefaultRateLimit，按这个值断言。
func TestMCPConsumeCallQuota(t *testing.T) {
	s := NewMCPService()
	calls := 0
	stubGovernance(t, nil, func(int64) (int64, error) {
		calls++
		return int64(calls), nil
	})
	key := &repo.APIKey{ID: 1, Scopes: []string{ScopeAssetsRead}}

	for i := 0; i < MCPDefaultRateLimit; i++ {
		if err := s.ConsumeCallQuota(context.Background(), key); err != nil {
			t.Fatalf("第 %d 次调用（限额 %d 内）不应拒绝: %v", i+1, MCPDefaultRateLimit, err)
		}
	}
	err := s.ConsumeCallQuota(context.Background(), key)
	rl, ok := err.(*ErrMCPRateLimited)
	if !ok {
		t.Fatalf("超限应返回 ErrMCPRateLimited，实际 %v", err)
	}
	if rl.RetryAfterSeconds < 1 || rl.RetryAfterSeconds > 60 {
		t.Fatalf("Retry-After 应在 1-60 秒内，实际 %d", rl.RetryAfterSeconds)
	}

	// 治理面不可用（nil）时放行。
	prev := mcpGovernance
	mcpGovernance = func() repo.MCPGovernanceRepo { return nil }
	if err := s.ConsumeCallQuota(context.Background(), key); err != nil {
		t.Fatalf("治理面不可用应放行: %v", err)
	}
	mcpGovernance = prev
}

// 配额查询失败放行：配额是运营护栏，不把瞬时故障放大成 MCP 不可用。
func TestMCPConsumeCallQuotaFailOpen(t *testing.T) {
	s := NewMCPService()
	stubGovernance(t, nil, func(int64) (int64, error) { return 0, context.DeadlineExceeded })
	key := &repo.APIKey{ID: 1}
	if err := s.ConsumeCallQuota(context.Background(), key); err != nil {
		t.Fatalf("配额查询失败应放行，实际 %v", err)
	}
}

// ToolMetas 与注册表一一对应，且写类工具的 Write 标记正确。
func TestMCPToolMetas(t *testing.T) {
	s := NewMCPService()
	metas := s.ToolMetas()
	if len(metas) != len(s.toolRegistry()) {
		t.Fatalf("ToolMetas 数量 %d 与注册表 %d 不一致", len(metas), len(s.toolRegistry()))
	}
	sawWrite := false
	for _, m := range metas {
		if m.Write {
			sawWrite = true
		}
	}
	if !sawWrite {
		t.Fatal("注册表里存在写/扫描类工具，ToolMetas 应至少标记一个 write=true")
	}
}
