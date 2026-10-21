package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/c1ayooo/4zreark/repo"
)

// assetTools 是资产域工具：查询、导入、人工验证、真实探测与失联治理。
func (s *MCPService) assetTools() []mcpToolHandler {
	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "list_projects",
				Title:       "列出可访问项目",
				Description: "列出当前 API key 可访问的项目。绑定项目的 key 只会返回该项目；未绑定的 key 返回全部项目。",
				InputSchema: inputSchema(map[string]any{}),
				Annotations: readOnlyAnnotations(),
			},
			AnyScopes: []string{ScopeAssetsRead, ScopeProjectsRead},
			Run: func(ctx context.Context, key *repo.APIKey, _ json.RawMessage) *mcpToolResult {
				return s.listProjects(ctx, key)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_project",
				Title:       "项目详情",
				Description: "读取项目资料与资产计数（资产数、原始记录数、失联数、种子数等）。绑定项目的 key 可省略 project_id。",
				InputSchema: inputSchema(map[string]any{
					"project_id": map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"},
				}),
				Annotations: readOnlyAnnotations(),
			},
			AnyScopes: []string{ScopeAssetsRead, ScopeProjectsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getProject(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "list_assets",
				Title:       "查询项目资产",
				Description: "按项目分页查询归并后的资产。kind 选择粒度（site/domain/ip），catalog 选择是否只看已确认资产，view 切换线索/候选/失联视图，q 支持平台 DSL 查询。",
				InputSchema: inputSchema(map[string]any{
					"project_id": map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"},
					"q":          map[string]any{"type": "string", "description": "查询串，支持平台 DSL（如 host=example.com、status=200、tech=nginx）"},
					"kind":       map[string]any{"type": "string", "enum": []string{"site", "domain", "ip"}, "default": "site", "description": "资产粒度"},
					"catalog":    map[string]any{"type": "string", "enum": []string{"all", "verified", "candidates"}, "default": "all", "description": "是否只看已确认资产"},
					"view":       map[string]any{"type": "string", "enum": []string{"", "clues", "candidates", "lost"}, "description": "线索/候选/失联视图，留空为全部"},
					"site_group": map[string]any{"type": "boolean", "default": true, "description": "true=按站点归并；false=展开到入口（仅 kind=site）"},
					"sort":       map[string]any{"type": "string", "enum": []string{"first_seen", "risk"}, "description": "排序：first_seen（默认）或 risk"},
					"page":       map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size":  map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeAssetsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listAssets(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_asset",
				Title:       "资产详情",
				Description: "读取单个站点的完整证据链：站点属性、全部入口、验证历史、指纹命中、原始记录、变更事件与关系边。site_id 来自 list_assets 的返回。",
				InputSchema: inputSchema(map[string]any{
					"site_id": map[string]any{"type": "integer", "minimum": 1, "description": "站点 ID（sites.id）"},
				}, "site_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeAssetsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getAsset(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "list_asset_routes",
				Title:       "站点路由",
				Description: "读取某个站点已采集的 URL 路由（方法、路径、状态码、首次/最近发现时间）。",
				InputSchema: inputSchema(map[string]any{
					"site_id": map[string]any{"type": "integer", "minimum": 1, "description": "站点 ID（sites.id）"},
					"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
				}, "site_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeAssetsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listAssetRoutes(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "list_events",
				Title:       "变更时间线",
				Description: "读取资产变更事件（首次发现、属性变化、验证结果等）。绑定项目的 key 只能看到该项目的事件。",
				InputSchema: inputSchema(map[string]any{
					"project_id": map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略；全项目 key 省略表示全部"},
					"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeAssetsRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listEvents(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "import_assets",
				Title:       "导入资产",
				Description: "把一批原始记录写入项目并归并到站点。写操作，会新增/更新资产与事件。records 每条至少包含 host，可选 port、protocol、value、status_code、title、ip、evidence。",
				InputSchema: inputSchema(map[string]any{
					"project_id": map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"},
					"source":     map[string]any{"type": "string", "description": "来源标识，默认 api", "default": "api"},
					"records": map[string]any{
						"type": "array", "minItems": 1, "maxItems": 5000,
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"host":        map[string]any{"type": "string"},
								"port":        map[string]any{"type": "integer"},
								"protocol":    map[string]any{"type": "string"},
								"value":       map[string]any{"type": "string"},
								"status_code": map[string]any{"type": "integer"},
								"title":       map[string]any{"type": "string"},
								"ip":          map[string]any{"type": "string"},
								"evidence":    map[string]any{"type": "object"},
							},
							"required": []string{"host"},
						},
					},
				}, "records"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeAssetsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.importAssets(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "verify_asset",
				Title:       "人工验证资产",
				Description: "写入一次人工验证结论（可达/不可达、状态码、原因），不发起网络请求。",
				InputSchema: inputSchema(map[string]any{
					"site_id":     map[string]any{"type": "integer", "minimum": 1},
					"reachable":   map[string]any{"type": "boolean", "description": "是否可达"},
					"status_code": map[string]any{"type": "integer", "description": "观测到的 HTTP 状态码"},
					"reason":      map[string]any{"type": "string", "description": "验证原因/备注"},
				}, "site_id", "reachable"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeAssetsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.verifyAsset(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "probe_asset",
				Title:       "真实探测资产",
				Description: "对站点发起真实 HTTP 探测，写回连通性、验证历史、指纹与事件。会产生网络流量。",
				InputSchema: inputSchema(map[string]any{
					"site_id": map[string]any{"type": "integer", "minimum": 1},
				}, "site_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeAssetsWrite, ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.probeAsset(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "protect_asset",
				Title:       "设置资产保护期",
				Description: "给站点设置人工删除保护期，期间不会被自动归档。",
				InputSchema: inputSchema(map[string]any{
					"site_id": map[string]any{"type": "integer", "minimum": 1},
					"days":    map[string]any{"type": "integer", "minimum": 1, "maximum": 3650, "default": 90},
				}, "site_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeAssetsWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.protectAsset(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "archive_lost",
				Title:       "归档失联资产",
				Description: "复核失联站点并归档仍不可达的资产。会发起真实探测；仅「全部项目」的 key 可用。建议先 dry_run=true 预演。",
				InputSchema: inputSchema(map[string]any{
					"days":    map[string]any{"type": "integer", "minimum": 1, "default": 30},
					"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 5000, "default": 100},
					"dry_run": map[string]any{"type": "boolean", "default": false},
				}),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeAssetsWrite, ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.archiveLost(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "recheck_assets",
				Title:       "批量复核资产",
				Description: "对指定站点批量重新探测并更新验证状态。会发起真实网络请求。",
				InputSchema: inputSchema(map[string]any{
					"site_ids": map[string]any{
						"type": "array", "minItems": 1, "maxItems": 500,
						"items": map[string]any{"type": "integer", "minimum": 1},
					},
				}, "site_ids"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeAssetsWrite, ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.recheckAssets(ctx, key, args)
			},
		},
	}
}

func (s *MCPService) listProjects(ctx context.Context, key *repo.APIKey) *mcpToolResult {
	if key.ProjectID != nil {
		p, err := s.assets.GetProject(ctx, *key.ProjectID)
		if err != nil {
			return toolError("读取项目失败: " + err.Error())
		}
		return toolOK(map[string]any{"items": []*repo.Project{p}, "total": 1})
	}
	items, err := s.assets.ListProjects(ctx)
	if err != nil {
		return toolError("读取项目列表失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": len(items)})
}

func (s *MCPService) getProject(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
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
	p, err := s.assets.GetProject(ctx, projectID)
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("项目不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return toolError("读取项目失败: " + err.Error())
	}
	return toolOK(p)
}

func (s *MCPService) listAssets(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
		Q         string `json:"q"`
		Kind      string `json:"kind"`
		Catalog   string `json:"catalog"`
		View      string `json:"view"`
		SiteGroup *bool  `json:"site_group"`
		Sort      string `json:"sort"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}

	siteGroup := true
	if args.SiteGroup != nil {
		siteGroup = *args.SiteGroup
	}
	pageSize := args.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	page := args.Page
	if page <= 0 {
		page = 1
	}

	pageResult, err := s.assets.ListAssets(ctx, repo.AssetQuery{
		ProjectID: projectID,
		Q:         args.Q,
		Kind:      args.Kind,
		Catalog:   args.Catalog,
		View:      args.View,
		SiteGroup: siteGroup,
		Sort:      args.Sort,
		Page:      page,
		PageSize:  pageSize,
	})
	if err != nil {
		if errors.Is(err, repo.ErrDSLSyntax) {
			return toolError("查询语法错误: " + err.Error())
		}
		return toolError("查询资产失败: " + err.Error())
	}
	return toolOK(pageResult)
}

func (s *MCPService) getAsset(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SiteID int64 `json:"site_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.SiteID <= 0 {
		return toolError("site_id 必填")
	}
	if err := ensureSiteAllowed(ctx, key, args.SiteID); err != nil {
		return toolError(err.Error())
	}
	detail, err := s.assets.GetAssetDetail(ctx, args.SiteID)
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("资产不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return toolError("读取资产详情失败: " + err.Error())
	}
	return toolOK(detail)
}

func (s *MCPService) listAssetRoutes(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SiteID int64 `json:"site_id"`
		Limit  int   `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.SiteID <= 0 {
		return toolError("site_id 必填")
	}
	if err := ensureSiteAllowed(ctx, key, args.SiteID); err != nil {
		return toolError(err.Error())
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	routes, err := s.assets.ListSiteRoutes(args.SiteID, limit)
	if err != nil {
		return toolError("读取站点路由失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": routes, "total": len(routes), "limit": limit})
}

func (s *MCPService) listEvents(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
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
	if args.Limit <= 0 {
		args.Limit = 50
	}
	rows, err := s.assets.RecentEventsByProject(ctx, projectID, args.Limit)
	if err != nil {
		return toolError("读取变更事件失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": rows, "total": len(rows), "limit": args.Limit})
}

func (s *MCPService) importAssets(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64           `json:"project_id"`
		Source    string           `json:"source"`
		Records   []repo.RawRecord `json:"records"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	if args.Source == "" {
		args.Source = "api"
	}
	res, err := s.assets.Ingest(ctx, projectID, args.Source, args.Records)
	if err != nil {
		return toolError("导入失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) verifyAsset(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SiteID     int64  `json:"site_id"`
		Reachable  bool   `json:"reachable"`
		StatusCode int    `json:"status_code"`
		Reason     string `json:"reason"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.SiteID <= 0 {
		return toolError("site_id 必填")
	}
	if err := ensureSiteAllowed(ctx, key, args.SiteID); err != nil {
		return toolError(err.Error())
	}
	if err := s.assets.VerifySite(ctx, args.SiteID, args.Reachable, args.StatusCode, args.Reason); err != nil {
		return toolError("写入验证结论失败: " + err.Error())
	}
	return toolOK(map[string]any{"site_id": args.SiteID, "reachable": args.Reachable, "status_code": args.StatusCode})
}

func (s *MCPService) probeAsset(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SiteID int64 `json:"site_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.SiteID <= 0 {
		return toolError("site_id 必填")
	}
	if err := ensureSiteAllowed(ctx, key, args.SiteID); err != nil {
		return toolError(err.Error())
	}
	report, err := NewVerifyService().ProbeSite(ctx, args.SiteID)
	if errors.Is(err, repo.ErrNotFound) {
		return toolError("资产不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return toolError("探测失败: " + err.Error())
	}
	return toolOK(report)
}

func (s *MCPService) protectAsset(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SiteID int64 `json:"site_id"`
		Days   int   `json:"days"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.SiteID <= 0 {
		return toolError("site_id 必填")
	}
	if err := ensureSiteAllowed(ctx, key, args.SiteID); err != nil {
		return toolError(err.Error())
	}
	if err := NewCleanupService().ProtectSite(ctx, args.SiteID, args.Days); err != nil {
		return toolError("设置保护期失败: " + err.Error())
	}
	if args.Days <= 0 {
		args.Days = 90
	}
	return toolOK(map[string]any{"site_id": args.SiteID, "protected_days": args.Days})
}

func (s *MCPService) archiveLost(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		Days   int  `json:"days"`
		Limit  int  `json:"limit"`
		DryRun bool `json:"dry_run"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.Days <= 0 {
		args.Days = 30
	}
	if args.Limit <= 0 {
		args.Limit = 100
	}
	report, err := NewCleanupService().ArchiveLost(ctx, args.Days, args.Limit, args.DryRun, "apikey:"+key.Name, "mcp")
	if err != nil {
		return toolError("归档失败: " + err.Error())
	}
	return toolOK(report)
}

func (s *MCPService) recheckAssets(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SiteIDs []int64 `json:"site_ids"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if len(args.SiteIDs) == 0 {
		return toolError("site_ids 不能为空")
	}
	if err := ensureSitesAllowed(ctx, key, args.SiteIDs); err != nil {
		return toolError(err.Error())
	}
	report, err := NewVerificationOpsService().Recheck(ctx, args.SiteIDs, "apikey:"+key.Name, "mcp")
	if err != nil {
		return toolError("批量复核失败: " + err.Error())
	}
	return toolOK(report)
}
