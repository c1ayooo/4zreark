package service

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
)

// enterpriseTools 是企业域工具：数据源清单、企业搜索、子公司深度采集（BFS）、
// 任务状态与采集上限。深度采集只写线索与候选域名，不创建站点、不触发扫描；
// 采集上限是全局配置，热更新（保存即对后续任务生效）。
func (s *MCPService) enterpriseTools() []mcpToolHandler {
	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "enterprise_providers",
				Title:       "企业数据源清单",
				Description: "列出已接入的企业数据源（爱企查/企查查/小蓝本等）及认证方式与可用状态。发起搜索或深度采集前先从这里选 provider。",
				InputSchema: inputSchema(map[string]any{}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeEnterpriseRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return toolOK(map[string]any{"items": s.enterprise.Providers()})
			},
		},
		{
			Tool: mcpTool{
				Name:        "enterprise_search",
				Title:       "搜索企业",
				Description: "按企业名关键词调用数据源搜索，返回候选企业（ext_id + 名称）。只检索不落库；深度采集前用它确认根企业。",
				InputSchema: inputSchema(map[string]any{
					"project_id": map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"},
					"provider":   map[string]any{"type": "string", "description": "数据源名，来自 enterprise_providers；缺省 aqc", "default": "aqc"},
					"keyword":    map[string]any{"type": "string", "description": "企业名关键词"},
					"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 20, "default": 10},
					"cookie":     map[string]any{"type": "string", "description": "cookie 类数据源的会话凭据；不传则回落已托管的会话"},
					"username":   map[string]any{"type": "string", "description": "账号类数据源的用户名；不传则回落已托管的会话"},
					"password":   map[string]any{"type": "string", "description": "账号类数据源的密码；不传则回落已托管的会话"},
				}, "keyword"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeEnterpriseRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.enterpriseSearch(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "enterprise_discover",
				Title:       "子公司深度采集",
				Description: "从根企业出发按层级 BFS 展开分支机构/对外投资（可选集团成员），采集域名入候选资产。写操作：只写线索与候选域名，不创建站点、不触发扫描。depth/max_nodes 会被服务端按当前采集上限钳制（上限可热更新）。ext_id 来自 enterprise_search。",
				InputSchema: inputSchema(map[string]any{
					"project_id":      map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"},
					"provider":        map[string]any{"type": "string", "description": "数据源名；缺省 aqc", "default": "aqc"},
					"ext_id":          map[string]any{"type": "string", "description": "根企业的数据源 ID（enterprise_search 返回的 ext_id）"},
					"name":            map[string]any{"type": "string", "description": "根企业名称（长度 ≤200）"},
					"depth":           map[string]any{"type": "integer", "minimum": 1, "description": "展开层级，按当前采集上限钳制"},
					"max_nodes":       map[string]any{"type": "integer", "minimum": 1, "description": "最大节点数，按当前采集上限钳制"},
					"collect_digital": map[string]any{"type": "boolean", "default": true, "description": "顺带采集数字资产（APP/小程序/公众号/新媒体）入候选池；仅小蓝本支持"},
					"collect_group":   map[string]any{"type": "boolean", "default": true, "description": "展开集团成员（同集团兄弟公司，计入节点上限）；仅小蓝本支持"},
					"cookie":          map[string]any{"type": "string", "description": "cookie 类数据源的会话凭据；不传则回落已托管的会话"},
					"username":        map[string]any{"type": "string", "description": "账号类数据源的用户名"},
					"password":        map[string]any{"type": "string", "description": "账号类数据源的密码"},
				}, "ext_id", "name"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeEnterpriseWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.enterpriseDiscover(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "enterprise_jobs",
				Title:       "深度采集任务列表",
				Description: "查看深度采集任务状态（running/done/error/canceled）与产出计数（节点/实体/域名）。采集中的任务会持续更新，可轮询。",
				InputSchema: inputSchema(map[string]any{
					"project_id": map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 只能看自己的；全项目 key 省略表示全部"},
					"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 30},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeEnterpriseRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.enterpriseJobs(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "enterprise_cancel_job",
				Title:       "取消深度采集任务",
				Description: "取消运行中的深度采集任务。已采集的部分保留，任务标记为 canceled。",
				InputSchema: inputSchema(map[string]any{
					"job_id": map[string]any{"type": "string", "description": "任务 ID（enterprise_jobs 返回）"},
				}, "job_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeEnterpriseWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.enterpriseCancelJob(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_enterprise_settings",
				Title:       "读取采集上限",
				Description: "读取子公司深度采集的硬上限：层级上限（max_depth）与节点上限（max_nodes）。所有任务的可配层级/节点都在此范围内钳制。",
				InputSchema: inputSchema(map[string]any{}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeEnterpriseRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				st, err := s.enterprise.EnterpriseSettings()
				if err != nil {
					return toolError("读取采集上限失败: " + err.Error())
				}
				return toolOK(st)
			},
		},
		{
			Tool: mcpTool{
				Name:        "update_enterprise_settings",
				Title:       "调整采集上限",
				Description: "调整子公司深度采集的硬上限（max_depth/max_nodes）。热更新：保存即生效，后续任务按新上限钳制，运行中任务不受影响，无需重启。全局配置，只对「全部项目」的 API key 开放。",
				InputSchema: inputSchema(map[string]any{
					"max_depth": map[string]any{"type": "integer", "minimum": 1, "description": "层级上限（≥1）"},
					"max_nodes": map[string]any{"type": "integer", "minimum": 1, "description": "节点上限（≥1）"},
				}),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeEnterpriseWrite},
			Run: func(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
				if err := requireGlobalKey(key); err != nil {
					return toolError(err.Error())
				}
				var args struct {
					MaxDepth *int64 `json:"max_depth"`
					MaxNodes *int64 `json:"max_nodes"`
				}
				if err := decodeArgs(raw, &args); err != nil {
					return toolError(err.Error())
				}
				if args.MaxDepth == nil && args.MaxNodes == nil {
					return toolError("至少提供 max_depth 或 max_nodes 之一")
				}
				in := map[string]any{}
				if args.MaxDepth != nil {
					in["max_depth"] = *args.MaxDepth
				}
				if args.MaxNodes != nil {
					in["max_nodes"] = *args.MaxNodes
				}
				if err := s.enterprise.SetEnterpriseSettings(in); err != nil {
					return toolError("保存采集上限失败: " + err.Error())
				}
				st, _ := s.enterprise.EnterpriseSettings()
				return toolOK(map[string]any{"message": "采集上限已更新并即时生效", "settings": st})
			},
		},
	}
}

func (s *MCPService) enterpriseSearch(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
		Provider  string `json:"provider"`
		Keyword   string `json:"keyword"`
		Limit     int    `json:"limit"`
		Cookie    string `json:"cookie"`
		Username  string `json:"username"`
		Password  string `json:"password"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	refs, err := s.enterprise.SearchProvider(ctx, EnterpriseCollectInput{
		ProjectID: projectID,
		Provider:  args.Provider,
		Keyword:   args.Keyword,
		Limit:     args.Limit,
		Cookie:    args.Cookie,
		Username:  args.Username,
		Password:  args.Password,
	})
	if err != nil {
		return toolError("企业搜索失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": refs, "total": len(refs)})
}

func (s *MCPService) enterpriseDiscover(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID      *int64 `json:"project_id"`
		Provider       string `json:"provider"`
		ExtID          string `json:"ext_id"`
		Name           string `json:"name"`
		Depth          int    `json:"depth"`
		MaxNodes       int    `json:"max_nodes"`
		CollectDigital *bool  `json:"collect_digital"`
		CollectGroup   *bool  `json:"collect_group"`
		Cookie         string `json:"cookie"`
		Username       string `json:"username"`
		Password       string `json:"password"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	job, err := s.enterprise.Discover(ctx, EnterpriseDiscoverInput{
		ProjectID:      projectID,
		Provider:       args.Provider,
		ExtID:          args.ExtID,
		Name:           args.Name,
		Owner:          "mcp:" + key.Name,
		Depth:          args.Depth,
		MaxNodes:       args.MaxNodes,
		CollectDigital: args.CollectDigital,
		CollectGroup:   args.CollectGroup,
		Cookie:         args.Cookie,
		Username:       args.Username,
		Password:       args.Password,
	})
	if err != nil {
		return toolError("启动深度采集失败: " + err.Error())
	}
	return toolOK(map[string]any{
		"job":    job,
		"notice": "采集在后台进行；用 enterprise_jobs 轮询状态。实际展开层级/节点数已被采集上限钳制。",
	})
}

func (s *MCPService) enterpriseJobs(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
		Limit     int    `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := optionalProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 30
	}
	if limit > 200 {
		limit = 200
	}
	jobs, err := s.enterprise.Jobs(ctx, projectID, limit)
	if err != nil {
		return toolError("读取任务失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": jobs, "total": len(jobs)})
}

func (s *MCPService) enterpriseCancelJob(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		JobID string `json:"job_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	// 项目边界的 key 只能取消自己项目里的任务；越权按不存在处理
	job, err := s.enterprise.Job(ctx, args.JobID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return toolError("任务不存在")
		}
		return toolError("读取任务失败: " + err.Error())
	}
	if pid, perr := strconv.ParseInt(job.ProjectID, 10, 64); perr == nil {
		if err := ensureProjectAllowed(key, pid); err != nil {
			return toolError("任务不存在或不在该 API key 的授权范围内")
		}
	}
	ok, err := s.enterprise.CancelJob(args.JobID)
	if err != nil {
		return toolError("取消任务失败: " + err.Error())
	}
	if !ok {
		return toolError("任务不在运行中，无需取消")
	}
	return toolOK(map[string]any{"job_id": args.JobID, "canceled": true})
}
