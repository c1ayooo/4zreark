package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/c1ayooo/4zreark/repo"
)

// governanceTools 覆盖种子 → 计划 → 批次 → 执行单元，以及关系/回放。
// 绑定项目的 key 只能操作自己项目的种子、计划与批次。
func (s *MCPService) governanceTools() []mcpToolHandler {
	projectIDProp := map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"}

	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "list_seeds",
				Title:       "列出种子",
				Description: "列出采集种子。绑定项目的 key 只返回自己的项目；全项目 key 可省略 project_id 表示全部。",
				InputSchema: inputSchema(map[string]any{"project_id": projectIDProp}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listSeeds(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "preview_seed",
				Title:       "预览种子展开",
				Description: "预览种子会展开出哪些目标，不落库。live=true 时会访问外部数据源（测绘/证书等），可能较慢。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
					"kind":       map[string]any{"type": "string", "enum": []string{"domain", "cidr", "company", "repo", "app", "dict"}},
					"value":      map[string]any{"type": "string", "description": "种子值"},
					"capability": map[string]any{"type": "object", "description": "扩展能力参数"},
					"live":       map[string]any{"type": "boolean", "default": false, "description": "是否访问外部数据源"},
				}, "kind", "value"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.previewSeed(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "create_seed",
				Title:       "新建种子",
				Description: "为项目新增采集种子。写操作。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
					"kind":       map[string]any{"type": "string", "enum": []string{"domain", "cidr", "company", "repo", "app", "dict"}},
					"value":      map[string]any{"type": "string"},
					"capability": map[string]any{"type": "object"},
				}, "kind", "value"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.createSeed(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "delete_seed",
				Title:       "删除种子",
				Description: "删除种子及其计划。破坏性操作。",
				InputSchema: inputSchema(map[string]any{
					"seed_id": map[string]any{"type": "integer", "minimum": 1},
				}, "seed_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.deleteSeed(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "list_plans",
				Title:       "列出计划",
				Description: "列出监控计划。绑定项目的 key 只返回自己的项目。",
				InputSchema: inputSchema(map[string]any{"project_id": projectIDProp}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listPlans(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "create_plan",
				Title:       "新建监控计划",
				Description: "在种子上创建周期计划，创建后立即到期。写操作。",
				InputSchema: inputSchema(map[string]any{
					"seed_id":        map[string]any{"type": "integer", "minimum": 1},
					"interval_hours": map[string]any{"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
					"budget":         map[string]any{"type": "object", "description": "预算参数"},
				}, "seed_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.createPlan(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "update_plan",
				Title:       "编辑监控计划",
				Description: "启停计划或修改间隔。未传字段保持不变。",
				InputSchema: inputSchema(map[string]any{
					"plan_id":        map[string]any{"type": "integer", "minimum": 1},
					"enabled":        map[string]any{"type": "boolean"},
					"interval_hours": map[string]any{"type": "integer", "minimum": 1, "maximum": 720},
				}, "plan_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.updatePlan(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "delete_plan",
				Title:       "删除监控计划",
				Description: "删除监控计划。破坏性操作。",
				InputSchema: inputSchema(map[string]any{
					"plan_id": map[string]any{"type": "integer", "minimum": 1},
				}, "plan_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.deletePlan(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "trigger_plan",
				Title:       "立即触发计划",
				Description: "为计划立即创建一个执行批次（同一分钟幂等）。写操作；live 种子可能访问外部数据源。",
				InputSchema: inputSchema(map[string]any{
					"plan_id": map[string]any{"type": "integer", "minimum": 1},
				}, "plan_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.triggerPlan(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "list_runs",
				Title:       "列出执行批次",
				Description: "列出治理批次。绑定项目的 key 只返回自己的项目。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
					"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listRuns(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_run",
				Title:       "批次详情",
				Description: "读取批次详情与执行单元状态计数。",
				InputSchema: inputSchema(map[string]any{
					"run_id": map[string]any{"type": "integer", "minimum": 1},
				}, "run_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getRun(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "list_run_targets",
				Title:       "列出执行单元",
				Description: "列出批次下的执行单元，可按状态过滤。",
				InputSchema: inputSchema(map[string]any{
					"run_id": map[string]any{"type": "integer", "minimum": 1},
					"state":  map[string]any{"type": "string", "description": "pending/running/done/failed/skipped"},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
				}, "run_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listRunTargets(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "execute_run",
				Title:       "执行批次",
				Description: "立即执行一批执行单元，会发起真实网络探测。写操作 + 扫描。",
				InputSchema: inputSchema(map[string]any{
					"run_id": map[string]any{"type": "integer", "minimum": 1},
					"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
				}, "run_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceWrite, ScopeScansRun},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.executeRun(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "rebuild_relations",
				Title:       "重建关系图谱",
				Description: "重建项目的关系边与证据。同步数据库操作。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
				}),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.rebuildRelations(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "replay_results",
				Title:       "回放历史结果",
				Description: "把历史 scan_results 回放为资产原始记录与站点。写操作。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
					"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 5000, "default": 5000},
				}),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeGovernanceWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.replayResults(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_relation_graph",
				Title:       "关系图谱",
				Description: "读取项目的关系图谱（按类型过滤、限量）。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
					"type":       map[string]any{"type": "string", "description": "关系类型，留空为全部"},
					"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 500},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.relationGraph(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_relation_status",
				Title:       "关系索引状态",
				Description: "读取项目关系图谱的索引状态与计数。",
				InputSchema: inputSchema(map[string]any{"project_id": projectIDProp}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeGovernanceRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.relationStatus(ctx, key, args)
			},
		},
	}
}

func (s *MCPService) listSeeds(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := optionalProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	items, err := s.governance.ListSeeds(ctx, projectID)
	if err != nil {
		return toolError("读取种子失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": len(items)})
}

func (s *MCPService) previewSeed(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID  *int64         `json:"project_id"`
		Kind       string         `json:"kind"`
		Value      string         `json:"value"`
		Capability map[string]any `json:"capability"`
		Live       bool           `json:"live"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.Live && !hasScope(key, ScopeScansRun) {
		return toolError("live=true 会访问外部数据源，需要 scans:run 权限")
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	res, err := s.governance.PreviewSeed(ctx, SeedPreviewRequest{
		ProjectID: projectID, Kind: args.Kind, Value: args.Value,
		Capability: args.Capability, Live: args.Live,
	})
	if err != nil {
		return toolError("预览失败: " + err.Error())
	}
	return toolOK(res)
}

func (s *MCPService) createSeed(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID  *int64         `json:"project_id"`
		Kind       string         `json:"kind"`
		Value      string         `json:"value"`
		Capability map[string]any `json:"capability"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	seed, err := s.governance.CreateSeed(ctx, projectID, args.Kind, args.Value, args.Capability)
	if err != nil {
		return toolError("创建种子失败: " + err.Error())
	}
	return toolOK(seed)
}

func (s *MCPService) seedFor(ctx context.Context, key *repo.APIKey, seedID int64) (*repo.Seed, error) {
	seed, err := s.governance.GetSeed(ctx, seedID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, errors.New("种子不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return nil, err
	}
	if err := ensureProjectAllowed(key, seed.ProjectID); err != nil {
		return nil, err
	}
	return seed, nil
}

func (s *MCPService) deleteSeed(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SeedID int64 `json:"seed_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.seedFor(ctx, key, args.SeedID); err != nil {
		return toolError(err.Error())
	}
	if err := s.governance.DeleteSeed(ctx, args.SeedID); err != nil {
		return toolError("删除种子失败: " + err.Error())
	}
	return toolOK(map[string]any{"seed_id": args.SeedID, "deleted": true})
}

func (s *MCPService) listPlans(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := optionalProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	items, err := s.governance.ListPlans(ctx, projectID)
	if err != nil {
		return toolError("读取计划失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": len(items)})
}

func (s *MCPService) createPlan(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		SeedID        int64          `json:"seed_id"`
		IntervalHours int            `json:"interval_hours"`
		Budget        map[string]any `json:"budget"`
		TriggerMode   string         `json:"trigger_mode"`
		CooldownMin   int            `json:"change_cooldown_minutes"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.seedFor(ctx, key, args.SeedID); err != nil {
		return toolError(err.Error())
	}
	plan, err := s.governance.CreatePlan(ctx, args.SeedID, args.IntervalHours, args.Budget, args.TriggerMode, args.CooldownMin)
	if err != nil {
		return toolError("创建计划失败: " + err.Error())
	}
	return toolOK(plan)
}

func (s *MCPService) planFor(ctx context.Context, key *repo.APIKey, planID int64) (*repo.Plan, error) {
	plan, err := s.governance.GetPlan(ctx, planID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, errors.New("计划不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return nil, err
	}
	if err := ensureProjectAllowed(key, plan.ProjectID); err != nil {
		return nil, err
	}
	return plan, nil
}

func (s *MCPService) updatePlan(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		PlanID        int64   `json:"plan_id"`
		Enabled       *bool   `json:"enabled"`
		IntervalHours *int    `json:"interval_hours"`
		TriggerMode   *string `json:"trigger_mode"`
		CooldownMin   *int    `json:"change_cooldown_minutes"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.planFor(ctx, key, args.PlanID); err != nil {
		return toolError(err.Error())
	}
	if err := s.governance.UpdatePlan(ctx, args.PlanID, args.Enabled, args.IntervalHours, args.TriggerMode, args.CooldownMin); err != nil {
		return toolError("更新计划失败: " + err.Error())
	}
	return toolOK(map[string]any{"plan_id": args.PlanID, "updated": true})
}

func (s *MCPService) deletePlan(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		PlanID int64 `json:"plan_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.planFor(ctx, key, args.PlanID); err != nil {
		return toolError(err.Error())
	}
	if err := s.governance.DeletePlan(ctx, args.PlanID); err != nil {
		return toolError("删除计划失败: " + err.Error())
	}
	return toolOK(map[string]any{"plan_id": args.PlanID, "deleted": true})
}

func (s *MCPService) triggerPlan(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		PlanID int64 `json:"plan_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.planFor(ctx, key, args.PlanID); err != nil {
		return toolError(err.Error())
	}
	run, created, err := s.governance.TriggerPlan(ctx, args.PlanID)
	if err != nil {
		return toolError("触发计划失败: " + err.Error())
	}
	return toolOK(map[string]any{"run": run, "created": created})
}

func (s *MCPService) listRuns(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
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
	items, err := s.governance.ListRuns(ctx, projectID, args.Limit)
	if err != nil {
		return toolError("读取批次失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": len(items)})
}

func (s *MCPService) runFor(ctx context.Context, key *repo.APIKey, runID int64) (*repo.Run, error) {
	run, _, err := s.governance.GetRun(ctx, runID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, errors.New("批次不存在或不在该 API key 的授权范围内")
	}
	if err != nil {
		return nil, err
	}
	if err := ensureProjectAllowed(key, run.ProjectID); err != nil {
		return nil, err
	}
	return run, nil
}

func (s *MCPService) getRun(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		RunID int64 `json:"run_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.runFor(ctx, key, args.RunID); err != nil {
		return toolError(err.Error())
	}
	run, stats, err := s.governance.GetRun(ctx, args.RunID)
	if err != nil {
		return toolError("读取批次失败: " + err.Error())
	}
	return toolOK(map[string]any{"run": run, "target_stats": stats})
}

func (s *MCPService) listRunTargets(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		RunID int64  `json:"run_id"`
		State string `json:"state"`
		Limit int    `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.runFor(ctx, key, args.RunID); err != nil {
		return toolError(err.Error())
	}
	items, err := s.governance.ListTargets(ctx, args.RunID, args.State, args.Limit)
	if err != nil {
		return toolError("读取执行单元失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": len(items)})
}

func (s *MCPService) executeRun(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		RunID int64 `json:"run_id"`
		Limit int   `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.runFor(ctx, key, args.RunID); err != nil {
		return toolError(err.Error())
	}
	stats, err := s.governance.ExecuteRun(ctx, args.RunID, args.Limit)
	if err != nil {
		return toolError("执行批次失败: " + err.Error())
	}
	return toolOK(stats)
}

func (s *MCPService) rebuildRelations(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
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
	stats, err := s.governance.RebuildRelations(ctx, projectID)
	if err != nil {
		return toolError("重建关系失败: " + err.Error())
	}
	return toolOK(map[string]any{"project_id": projectID, "by_type": stats})
}

func (s *MCPService) replayResults(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
		Limit     int    `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	stats, err := s.governance.ReplayResults(ctx, projectID, args.Limit)
	if err != nil {
		return toolError("回放失败: " + err.Error())
	}
	return toolOK(stats)
}

func (s *MCPService) relationGraph(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
		Type      string `json:"type"`
		Limit     int    `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := optionalProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	graph, err := s.governance.RelationGraph(ctx, projectID, args.Type, args.Limit)
	if err != nil {
		return toolError("读取关系图谱失败: " + err.Error())
	}
	return toolOK(graph)
}

func (s *MCPService) relationStatus(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := optionalProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	status, err := s.governance.RelationStatus(ctx, projectID)
	if err != nil {
		return toolError("读取关系索引状态失败: " + err.Error())
	}
	return toolOK(status)
}
