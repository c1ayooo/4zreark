package service

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
)

// pocTools 是 POC 模板管理工具。POC 是全局资源，仅对「全部项目」的 key 开放。
func (s *MCPService) pocTools() []mcpToolHandler {
	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "list_pocs",
				Title:       "列出 POC",
				Description: "分页列出 POC 模板，可按类型、严重度、启停状态与关键字过滤。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"page":      map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size": map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
					"type":      map[string]any{"type": "string"},
					"severity":  map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
					"enabled":   map[string]any{"type": "boolean"},
					"search":    map[string]any{"type": "string"},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopePOCsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listPOCs(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_poc",
				Title:       "POC 详情",
				Description: "按 ID 读取 POC 模板。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"poc_id": map[string]any{"type": "string", "description": "POC ID（24 位十六进制）"},
				}, "poc_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopePOCsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getPOC(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_poc_stats",
				Title:       "POC 统计",
				Description: "读取 POC 总数、启用数与按严重度/类型分布。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopePOCsRead},
			Run: func(ctx context.Context, key *repo.APIKey, _ json.RawMessage) *mcpToolResult {
				return s.getPOCStats(ctx, key)
			},
		},
		{
			Tool: mcpTool{
				Name:        "create_poc",
				Title:       "创建 POC",
				Description: "从 nuclei YAML 内容创建/更新 POC 模板。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"content": map[string]any{"type": "string", "description": "nuclei 模板 YAML 全文"},
					"enabled": map[string]any{"type": "boolean", "default": true},
				}, "content"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopePOCsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.createPOC(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "update_poc",
				Title:       "编辑 POC",
				Description: "修改 POC 元数据或内容。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"poc_id": map[string]any{"type": "string"},
					"updates": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"name":        map[string]any{"type": "string"},
							"description": map[string]any{"type": "string"},
							"author":      map[string]any{"type": "string"},
							"severity":    map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
							"type":        map[string]any{"type": "string"},
							"tags":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"content":     map[string]any{"type": "string"},
							"cve_id":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"references":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"enabled":     map[string]any{"type": "boolean"},
							"version":     map[string]any{"type": "string"},
							"source":      map[string]any{"type": "string"},
						},
					},
				}, "poc_id", "updates"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopePOCsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.updatePOC(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "delete_poc",
				Title:       "删除 POC",
				Description: "删除 POC 模板。破坏性操作；仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"poc_id": map[string]any{"type": "string"},
				}, "poc_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopePOCsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.deletePOC(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "toggle_poc",
				Title:       "启停 POC",
				Description: "启用或停用 POC 模板。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"poc_id":  map[string]any{"type": "string"},
					"enabled": map[string]any{"type": "boolean"},
				}, "poc_id", "enabled"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopePOCsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.togglePOC(ctx, key, args)
			},
		},
	}
}

func (s *MCPService) listPOCs(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		Page     int64  `json:"page"`
		PageSize int64  `json:"page_size"`
		Type     string `json:"type"`
		Severity string `json:"severity"`
		Enabled  *bool  `json:"enabled"`
		Search   string `json:"search"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.Page <= 0 {
		args.Page = 1
	}
	if args.PageSize <= 0 {
		args.PageSize = 20
	}
	if args.PageSize > 100 {
		args.PageSize = 100
	}
	res, err := s.pocs.List(POCListParams{
		Page: args.Page, PageSize: args.PageSize, Type: args.Type,
		Severity: args.Severity, Enabled: args.Enabled, Search: args.Search,
	})
	if err != nil {
		return toolError("读取 POC 失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) getPOC(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		POCID string `json:"poc_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	poc, err := s.pocs.GetByID(args.POCID)
	if err != nil {
		return toolError("POC 不存在: " + err.Error())
	}
	return toolOK(poc)
}

func (s *MCPService) getPOCStats(ctx context.Context, key *repo.APIKey) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	stats, err := s.pocs.GetStatistics()
	if err != nil {
		return toolError("读取 POC 统计失败: " + err.Error())
	}
	return toolOK(stats)
}

func (s *MCPService) createPOC(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		Content string `json:"content"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if strings.TrimSpace(args.Content) == "" {
		return toolError("content 必填")
	}
	poc, err := ParseNucleiTemplateYAML([]byte(args.Content))
	if err != nil {
		return toolError("解析模板失败: " + err.Error())
	}
	if args.Enabled != nil {
		poc.Enabled = *args.Enabled
	} else {
		poc.Enabled = true
	}
	if err := s.pocs.Create(poc); err != nil {
		return toolError("创建 POC 失败: " + err.Error())
	}
	return toolOK(map[string]any{"id": poc.ID.Hex(), "name": poc.Name, "template_id": poc.TemplateID, "enabled": poc.Enabled})
}

func (s *MCPService) updatePOC(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		POCID   string         `json:"poc_id"`
		Updates map[string]any `json:"updates"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	allowed := map[string]bool{
		"name": true, "description": true, "author": true, "severity": true, "type": true,
		"tags": true, "content": true, "cve_id": true, "references": true, "enabled": true,
		"version": true, "source": true,
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
	if err := s.pocs.Update(args.POCID, updates); err != nil {
		return toolError("更新 POC 失败: " + err.Error())
	}
	return toolOK(map[string]any{"poc_id": args.POCID, "updated": true})
}

func (s *MCPService) deletePOC(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		POCID string `json:"poc_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.pocs.Delete(args.POCID); err != nil {
		return toolError("删除 POC 失败: " + err.Error())
	}
	return toolOK(map[string]any{"poc_id": args.POCID, "deleted": true})
}

func (s *MCPService) togglePOC(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		POCID   string `json:"poc_id"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if err := s.pocs.ToggleEnabled(args.POCID, args.Enabled); err != nil {
		return toolError("启停 POC 失败: " + err.Error())
	}
	return toolOK(map[string]any{"poc_id": args.POCID, "enabled": args.Enabled})
}
