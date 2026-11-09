package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/repo"
)

// 代码审计（sentinel）域工具的权限与边界。断言全部落在触碰数据层之前
// （scope 门 / llm:invoke 门 / 参数校验），不依赖数据库；
// 判定落库与 evidence 防幻觉校验本体由 sentinel_judge / eval 层测试覆盖。

func sentinelCall(t *testing.T, s *MCPService, scopes []string, projectID *int64, name string, args map[string]any) *mcpToolResult {
	t.Helper()
	key := &repo.APIKey{ID: 1, Name: "tester", Scopes: scopes, ProjectID: projectID}
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	resp, err := s.Handle(context.Background(), &RPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params,
	}, key)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	return resp.Result.(*mcpToolResult)
}

func TestMCPSentinelToolScopes(t *testing.T) {
	s := NewMCPService()

	// 缺 sentinel:read：读工具拒绝
	if res := sentinelCall(t, s, []string{ScopeAssetsRead}, nil, "sentinel_list_repos", map[string]any{}); !res.IsError || !strings.Contains(res.Content[0].Text, ScopeSentinelRead) {
		t.Fatalf("缺少 sentinel:read 时应拒绝，实际 %+v", res)
	}
	// 只有读没有写：回写类工具拒绝
	if res := sentinelCall(t, s, []string{ScopeSentinelRead}, nil, "sentinel_submit_judgment", map[string]any{}); !res.IsError || !strings.Contains(res.Content[0].Text, ScopeSentinelWrite) {
		t.Fatalf("缺少 sentinel:write 时提交判定应拒绝，实际 %+v", res)
	}
	// sentinel:write 齐但无 llm:invoke：平台模型工具拒绝
	if res := sentinelCall(t, s, []string{ScopeSentinelWrite}, nil, "sentinel_judge_commit", map[string]any{"commit_id": 1}); !res.IsError || !strings.Contains(res.Content[0].Text, ScopeLLMInvoke) {
		t.Fatalf("缺少 llm:invoke 时内部判定应拒绝，实际 %+v", res)
	}
	if res := sentinelCall(t, s, []string{ScopeSentinelWrite}, nil, "sentinel_generate_nuclei", map[string]any{"finding_id": 1}); !res.IsError || !strings.Contains(res.Content[0].Text, ScopeLLMInvoke) {
		t.Fatalf("缺少 llm:invoke 时模板生成应拒绝，实际 %+v", res)
	}
	// 项目绑定的 key：即使有读权限也进不了哨兵域（数据无项目维度）
	bound := int64(1)
	if res := sentinelCall(t, s, []string{ScopeSentinelRead}, &bound, "sentinel_list_repos", map[string]any{}); !res.IsError || !strings.Contains(res.Content[0].Text, "全部项目") {
		t.Fatalf("绑定项目的 key 调哨兵工具应拒绝，实际 %+v", res)
	}
}

// llm:invoke 是「平台模型额度」的密钥级开关：没勾选的 key 在 tools/list 里
// 根本看不到 LLM 工具（提示词空间也收敛），勾选后才出现。
func TestMCPSentinelLLMToolsHiddenWithoutInvoke(t *testing.T) {
	s := NewMCPService()
	stubGovernance(t, nil, nil)

	listTools := func(scopes []string) []string {
		t.Helper()
		resp, err := s.Handle(context.Background(), &RPCRequest{
			JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/list",
		}, &repo.APIKey{ID: 1, Scopes: scopes})
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		raw, _ := json.Marshal(resp.Result.(map[string]any)["tools"])
		var tools []mcpTool
		if err := json.Unmarshal(raw, &tools); err != nil {
			t.Fatalf("解析 tools: %v", err)
		}
		names := make([]string, 0, len(tools))
		for _, tool := range tools {
			names = append(names, tool.Name)
		}
		return names
	}

	has := func(names []string, want string) bool {
		for _, n := range names {
			if n == want {
				return true
			}
		}
		return false
	}

	auditOnly := listTools([]string{ScopeSentinelRead, ScopeSentinelWrite})
	if !has(auditOnly, "sentinel_submit_judgment") || !has(auditOnly, "sentinel_list_repos") {
		t.Fatal("代码审计 key 应看到审计读写工具")
	}
	if has(auditOnly, "sentinel_judge_commit") || has(auditOnly, "sentinel_generate_nuclei") {
		t.Fatal("未授 llm:invoke 的 key 不应看到平台模型工具")
	}

	withLLM := listTools([]string{ScopeSentinelRead, ScopeSentinelWrite, ScopeLLMInvoke})
	if !has(withLLM, "sentinel_judge_commit") || !has(withLLM, "sentinel_generate_nuclei") {
		t.Fatal("授予 llm:invoke 后应看到平台模型工具")
	}
}

// 新 scope 进入白名单：签发/校验路径可用。
func TestMCPSentinelScopesInCatalog(t *testing.T) {
	got, err := ValidateScopes([]string{"sentinel:read", "llm:invoke"})
	if err != nil || len(got) != 2 {
		t.Fatalf("新 scope 应通过白名单校验，实际 %v/%v", got, err)
	}
	for _, want := range []string{ScopeSentinelRead, ScopeSentinelWrite, ScopeLLMInvoke} {
		if !scopeSet[want] {
			t.Fatalf("scope %s 未进目录", want)
		}
	}
}

// 外部判定的参数门：reasoning 必填在触碰数据层之前拒绝。
func TestMCPSentinelSubmitJudgmentArgGate(t *testing.T) {
	s := NewMCPService()
	res := sentinelCall(t, s, []string{ScopeSentinelWrite}, nil, "sentinel_submit_judgment", map[string]any{
		"commit_id": 1, "is_security_fix": true, "vuln_class": "SQLI",
		"severity": "high", "confidence": 0.9,
	})
	if !res.IsError || !strings.Contains(res.Content[0].Text, "reasoning") {
		t.Fatalf("缺 reasoning 应在参数校验层拒绝，实际 %+v", res)
	}
}
