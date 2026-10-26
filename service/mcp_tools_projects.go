package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/c1ayooo/4zreark/repo"
)

// projectTools 是项目生命周期工具。绑定项目的 key 只能管理自己的项目；
// 新建与删除项目会改变授权边界，只对「全部项目」的 key 开放。
func (s *MCPService) projectTools() []mcpToolHandler {
	projectIDProp := map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"}

	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "create_project",
				Title:       "新建项目",
				Description: "创建资产归属项目。写操作；仅「全部项目」的 key 可用。code 只允许字母/数字/下划线/短横线。",
				InputSchema: inputSchema(map[string]any{
					"code":                map[string]any{"type": "string", "description": "项目编码，1..64 位字母/数字/_/-"},
					"name":                map[string]any{"type": "string", "description": "项目名称，必填"},
					"region":              map[string]any{"type": "string", "description": "地区，默认 domestic"},
					"description":         map[string]any{"type": "string"},
					"homepage_url":        map[string]any{"type": "string", "description": "完整 URL"},
					"color":               map[string]any{"type": "string", "description": "展示色，如 #64748b"},
					"cycle_interval_days": map[string]any{"type": "integer", "minimum": 1, "maximum": 3650, "default": 30},
				}, "code", "name"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeProjectsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.createProject(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "update_project",
				Title:       "编辑项目",
				Description: "修改项目资料。未传的字段保持不变；绑定项目的 key 只能改自己的项目。",
				InputSchema: inputSchema(map[string]any{
					"project_id":          projectIDProp,
					"code":                map[string]any{"type": "string"},
					"name":                map[string]any{"type": "string"},
					"region":              map[string]any{"type": "string"},
					"description":         map[string]any{"type": "string"},
					"homepage_url":        map[string]any{"type": "string"},
					"color":               map[string]any{"type": "string"},
					"cycle_interval_days": map[string]any{"type": "integer", "minimum": 1, "maximum": 3650},
				}),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeProjectsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.updateProject(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "pause_project",
				Title:       "暂停项目采集",
				Description: "暂停项目的资产采集与治理推进，可附原因。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
					"reason":     map[string]any{"type": "string"},
				}),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeProjectsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.setProjectPaused(ctx, key, args, true)
			},
		},
		{
			Tool: mcpTool{
				Name:        "resume_project",
				Title:       "恢复项目采集",
				Description: "恢复项目的资产采集与治理推进。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
				}),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeProjectsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.setProjectPaused(ctx, key, args, false)
			},
		},
		{
			Tool: mcpTool{
				Name:        "delete_project",
				Title:       "删除项目",
				Description: "删除项目及其资产、种子、任务归属数据。破坏性操作；仅「全部项目」的 key 可用，且 confirm_code 必须等于项目 code。",
				InputSchema: inputSchema(map[string]any{
					"project_id":   map[string]any{"type": "integer", "minimum": 1},
					"confirm_code": map[string]any{"type": "string", "description": "必须与项目 code 完全一致"},
				}, "project_id", "confirm_code"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeProjectsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.deleteProject(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_project_collection_state",
				Title:       "项目采集状态",
				Description: "读取项目采集状态：暂停原因、最近批次、种子/计划计数等。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeProjectsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.projectCollectionState(ctx, key, args)
			},
		},
	}
}

func (s *MCPService) createProject(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		Code        string `json:"code"`
		Name        string `json:"name"`
		Region      string `json:"region"`
		Description string `json:"description"`
		HomepageURL string `json:"homepage_url"`
		Color       string `json:"color"`
		CycleDays   int    `json:"cycle_interval_days"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	p, err := s.assets.CreateProject(ctx, repo.ProjectInput{
		Code: args.Code, Name: args.Name, Region: args.Region, Description: args.Description,
		HomepageURL: args.HomepageURL, Color: args.Color, CycleDays: args.CycleDays,
	})
	if err != nil {
		return toolError("创建项目失败: " + err.Error())
	}
	return toolOK(p)
}

func (s *MCPService) updateProject(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID   *int64  `json:"project_id"`
		Code        *string `json:"code"`
		Name        *string `json:"name"`
		Region      *string `json:"region"`
		Description *string `json:"description"`
		HomepageURL *string `json:"homepage_url"`
		Color       *string `json:"color"`
		CycleDays   *int    `json:"cycle_interval_days"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	current, err := s.assets.GetProject(ctx, projectID)
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("项目不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return toolError("读取项目失败: " + err.Error())
	}
	in := repo.ProjectInput{
		Code: current.Code, Name: current.Name, Region: current.Region,
		Description: current.Description, HomepageURL: current.HomepageURL,
		Color: current.Color, CycleDays: current.CycleDays,
	}
	if args.Code != nil {
		in.Code = *args.Code
	}
	if args.Name != nil {
		in.Name = *args.Name
	}
	if args.Region != nil {
		in.Region = *args.Region
	}
	if args.Description != nil {
		in.Description = *args.Description
	}
	if args.HomepageURL != nil {
		in.HomepageURL = *args.HomepageURL
	}
	if args.Color != nil {
		in.Color = *args.Color
	}
	if args.CycleDays != nil {
		in.CycleDays = *args.CycleDays
	}
	p, err := s.assets.UpdateProject(ctx, projectID, in)
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("项目不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return toolError("更新项目失败: " + err.Error())
	}
	return toolOK(p)
}

func (s *MCPService) setProjectPaused(ctx context.Context, key *repo.APIKey, raw json.RawMessage, paused bool) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
		Reason    string `json:"reason"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	p, err := s.assets.SetProjectPaused(ctx, projectID, paused, args.Reason)
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("项目不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return toolError("更新项目状态失败: " + err.Error())
	}
	return toolOK(p)
}

func (s *MCPService) deleteProject(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		ProjectID   int64  `json:"project_id"`
		ConfirmCode string `json:"confirm_code"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.ProjectID <= 0 || args.ConfirmCode == "" {
		return toolError("project_id 与 confirm_code 必填")
	}
	res, err := NewProjectOpsService().Delete(ctx, args.ProjectID, args.ConfirmCode, "apikey:"+key.Name, "mcp")
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("项目不存在")
	}
	if err != nil {
		return toolError("删除项目失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) projectCollectionState(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	state, err := NewProjectOpsService().CollectionState(ctx, projectID)
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("项目不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return toolError("读取采集状态失败: " + err.Error())
	}
	return toolOK(state)
}
