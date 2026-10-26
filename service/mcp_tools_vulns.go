package service

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
)

// vulnTools 是漏洞域工具。漏洞模型没有 project_id，当前只对「全部项目」的 key 开放，
// 避免绑定项目的 key 读到其它项目的数据。
func (s *MCPService) vulnTools() []mcpToolHandler {
	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "list_vulnerabilities",
				Title:       "列出漏洞",
				Description: "分页列出漏洞，可按严重度、状态、关键字过滤。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string", "description": "工作区 ID，留空为全部"},
					"severity":     map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
					"status":       map[string]any{"type": "string", "enum": []string{"new", "confirmed", "fixed", "ignored", "false_positive"}},
					"keyword":      map[string]any{"type": "string"},
					"page":         map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size":    map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 10},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeVulnsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listVulnerabilities(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_vulnerability",
				Title:       "漏洞详情",
				Description: "按 ID 读取漏洞详情。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"vuln_id": map[string]any{"type": "string", "description": "漏洞 ID（24 位十六进制）"},
				}, "vuln_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeVulnsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getVulnerability(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "create_vulnerability",
				Title:       "创建漏洞",
				Description: "人工录入漏洞；会先做指纹查重并返回候选。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string"},
					"asset_id":     map[string]any{"type": "string"},
					"task_id":      map[string]any{"type": "string"},
					"name":         map[string]any{"type": "string"},
					"description":  map[string]any{"type": "string"},
					"severity":     map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
					"type":         map[string]any{"type": "string"},
					"target":       map[string]any{"type": "string"},
					"method":       map[string]any{"type": "string"},
					"payload":      map[string]any{"type": "string"},
					"evidence":     map[string]any{"type": "string"},
					"request":      map[string]any{"type": "string"},
					"response":     map[string]any{"type": "string"},
					"cve_id":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"references":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"solution":     map[string]any{"type": "string"},
					"tags":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				}, "name", "severity", "target"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeVulnsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.createVulnerability(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "update_vulnerability",
				Title:       "编辑漏洞",
				Description: "修改漏洞字段。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"vuln_id": map[string]any{"type": "string"},
					"updates": map[string]any{"type": "object", "description": "允许 name/description/severity/type/target/method/payload/evidence/request/response/solution/cve_id/cnnvd_id/references/tags"},
				}, "vuln_id", "updates"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeVulnsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.updateVulnerability(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "delete_vulnerability",
				Title:       "删除漏洞",
				Description: "删除漏洞。破坏性操作；仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"vuln_id": map[string]any{"type": "string"},
				}, "vuln_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeVulnsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.deleteVulnerability(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "set_vulnerability_status",
				Title:       "修改漏洞状态",
				Description: "标记漏洞为已修复/已忽略/误报。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"vuln_id": map[string]any{"type": "string"},
					"status":  map[string]any{"type": "string", "enum": []string{"fixed", "ignored", "false_positive"}},
				}, "vuln_id", "status"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeVulnsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.setVulnerabilityStatus(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "verify_vulnerability",
				Title:       "复核漏洞",
				Description: "用 nuclei 对漏洞做一次真实复核（会发起网络请求）。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"vuln_id": map[string]any{"type": "string"},
				}, "vuln_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeVulnsWrite, ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.verifyVulnerability(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_vuln_stats",
				Title:       "漏洞统计",
				Description: "读取漏洞汇总统计。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string"},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeVulnsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getVulnStats(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_vuln_statistics",
				Title:       "漏洞详细统计",
				Description: "读取漏洞趋势、分布等详细统计。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string"},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeVulnsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getVulnStatistics(ctx, key, args)
			},
		},
	}
}

func (s *MCPService) listVulnerabilities(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		WorkspaceID string `json:"workspace_id"`
		Severity    string `json:"severity"`
		Status      string `json:"status"`
		Keyword     string `json:"keyword"`
		Page        int    `json:"page"`
		PageSize    int    `json:"page_size"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.Page <= 0 {
		args.Page = 1
	}
	if args.PageSize <= 0 {
		args.PageSize = 10
	}
	if args.PageSize > 100 {
		args.PageSize = 100
	}
	items, total, err := s.vulns.ListVulnerabilities(args.WorkspaceID, args.Severity, args.Status,
		args.Keyword, args.Page, args.PageSize)
	if err != nil {
		return toolError("读取漏洞失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": total, "page": args.Page, "page_size": args.PageSize})
}

func (s *MCPService) getVulnerability(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		VulnID string `json:"vuln_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	vuln, err := s.vulns.GetVulnByID(args.VulnID)
	if err != nil {
		return toolError("漏洞不存在: " + err.Error())
	}
	return toolOK(vuln)
}

func (s *MCPService) createVulnerability(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		WorkspaceID string              `json:"workspace_id"`
		AssetID     string              `json:"asset_id"`
		TaskID      string              `json:"task_id"`
		Name        string              `json:"name"`
		Description string              `json:"description"`
		Severity    models.VulnSeverity `json:"severity"`
		Type        string              `json:"type"`
		Target      string              `json:"target"`
		Method      string              `json:"method"`
		Payload     string              `json:"payload"`
		Evidence    string              `json:"evidence"`
		Request     string              `json:"request"`
		Response    string              `json:"response"`
		CVEID       []string            `json:"cve_id"`
		References  []string            `json:"references"`
		Solution    string              `json:"solution"`
		Tags        []string            `json:"tags"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if strings.TrimSpace(args.Name) == "" || strings.TrimSpace(args.Target) == "" || args.Severity == "" {
		return toolError("name、severity、target 必填")
	}
	vuln := &models.Vulnerability{
		Name: args.Name, Description: args.Description, Severity: args.Severity,
		Type: args.Type, Target: args.Target, Method: args.Method, Payload: args.Payload,
		Evidence: args.Evidence, Request: args.Request, Response: args.Response,
		CVEID: args.CVEID, References: args.References, Solution: args.Solution,
		Tags: args.Tags, Scanner: "manual",
	}
	if args.WorkspaceID != "" {
		id, err := oid.ObjectIDFromHex(args.WorkspaceID)
		if err != nil {
			return toolError("workspace_id 非法")
		}
		vuln.WorkspaceID = id
	}
	if args.AssetID != "" {
		id, err := oid.ObjectIDFromHex(args.AssetID)
		if err != nil {
			return toolError("asset_id 非法")
		}
		vuln.AssetID = id
	}
	if args.TaskID != "" {
		id, err := oid.ObjectIDFromHex(args.TaskID)
		if err != nil {
			return toolError("task_id 非法")
		}
		vuln.TaskID = id
	}
	duplicates, _ := s.vulns.FindDuplicates(ctx, vuln)
	if err := s.vulns.CreateVulnerability(vuln); err != nil {
		return toolError("创建漏洞失败: " + err.Error())
	}
	return toolOK(map[string]any{"id": vuln.ID.Hex(), "duplicates": duplicates})
}

func (s *MCPService) updateVulnerability(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		VulnID  string         `json:"vuln_id"`
		Updates map[string]any `json:"updates"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	allowed := map[string]bool{
		"name": true, "description": true, "severity": true, "type": true, "target": true,
		"method": true, "payload": true, "evidence": true, "request": true, "response": true,
		"solution": true, "cve_id": true, "cnnvd_id": true, "references": true, "tags": true,
	}
	updates := make(map[string]any, len(args.Updates))
	for k, v := range args.Updates {
		if !allowed[k] {
			return toolError("不允许修改字段: " + k)
		}
		updates[k] = v
	}
	if len(updates) == 0 {
		return toolError("updates 不能为空")
	}
	if err := s.vulns.UpdateVulnerability(args.VulnID, updates); err != nil {
		return toolError("更新漏洞失败: " + err.Error())
	}
	return toolOK(map[string]any{"vuln_id": args.VulnID, "updated": true})
}

func (s *MCPService) deleteVulnerability(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		VulnID string `json:"vuln_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.vulns.DeleteVulnerability(args.VulnID); err != nil {
		return toolError("删除漏洞失败: " + err.Error())
	}
	return toolOK(map[string]any{"vuln_id": args.VulnID, "deleted": true})
}

func (s *MCPService) setVulnerabilityStatus(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		VulnID string `json:"vuln_id"`
		Status string `json:"status"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	var err error
	switch models.VulnStatus(args.Status) {
	case models.VulnStatusFixed:
		err = s.vulns.MarkAsFixed(args.VulnID, "apikey:"+key.Name)
	case models.VulnStatusIgnored:
		err = s.vulns.MarkAsIgnored(args.VulnID)
	case models.VulnStatusFalse:
		err = s.vulns.MarkAsFalsePositive(args.VulnID)
	default:
		return toolError("status 只支持 fixed / ignored / false_positive")
	}
	if err != nil {
		return toolError("修改漏洞状态失败: " + err.Error())
	}
	return toolOK(map[string]any{"vuln_id": args.VulnID, "status": args.Status})
}

func (s *MCPService) verifyVulnerability(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		VulnID string `json:"vuln_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	vuln, confirmed, err := s.vulns.VerifyVulnerability(args.VulnID)
	if err != nil {
		return toolError("复核失败: " + err.Error())
	}
	return toolOK(map[string]any{"vulnerability": vuln, "confirmed": confirmed})
}

func (s *MCPService) getVulnStats(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		WorkspaceID string `json:"workspace_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	stats, err := s.vulns.GetVulnStats(args.WorkspaceID)
	if err != nil {
		return toolError("读取漏洞统计失败: " + err.Error())
	}
	return toolOK(stats)
}

func (s *MCPService) getVulnStatistics(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		WorkspaceID string `json:"workspace_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	stats, err := s.vulns.GetVulnStatistics(args.WorkspaceID)
	if err != nil {
		return toolError("读取漏洞统计失败: " + err.Error())
	}
	return toolOK(stats)
}
