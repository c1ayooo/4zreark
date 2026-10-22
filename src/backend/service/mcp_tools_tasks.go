package service

import (
	"context"
	"time"
	"encoding/json"
	"errors"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// taskTools 覆盖任务 CRUD、生命周期与结果读取。
// 绑定项目的 key 只能操作自己项目的任务；任务一旦启动会由后台 worker 执行真实扫描。
func (s *MCPService) taskTools() []mcpToolHandler {
	taskIDProp := map[string]any{"type": "string", "description": "任务 ID（24 位十六进制）"}
	projectIDProp := map[string]any{"type": "integer", "minimum": 1, "description": "项目 ID；绑定项目的 key 可省略"}
	resultTypeProp := map[string]any{
		"type":        "string",
		"enum":        []string{"", "subdomain", "takeover", "app", "miniapp", "url", "crawler", "sensitive", "dirscan", "vuln", "monitor", "port", "service", "exposure", "clue"},
		"description": "结果类型；留空为全部",
	}

	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "list_tasks",
				Title:       "列出任务",
				Description: "按项目、类型、状态分页列出扫描任务。绑定项目的 key 只返回自己的项目。",
				InputSchema: inputSchema(map[string]any{
					"project_id": projectIDProp,
					"type":       map[string]any{"type": "string", "description": "任务类型，如 full / port_scan / vuln_scan"},
					"status":     map[string]any{"type": "string", "enum": []string{"pending", "running", "paused", "completed", "failed", "cancelled"}},
					"page":       map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size":  map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 10},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeTasksRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.listTasks(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_task",
				Title:       "任务详情",
				Description: "读取任务配置、状态、进度与结果统计。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeTasksRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getTask(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "wait_task",
				Title:       "等待任务完成",
				Description: "服务端轮询任务状态，直到终态（completed / failed / cancelled / paused）或本次调用超时。超时返回 finished=false 与当前进度，请再次调用本工具继续等待——本服务是无状态 JSON-RPC，没有任务完成推送，wait_task 是 agent 感知任务结束的唯一通道。只读。",
				InputSchema: inputSchema(map[string]any{
					"task_id": taskIDProp,
					"timeout_seconds": map[string]any{
						"type": "integer", "minimum": 1, "maximum": 90, "default": 30,
						"description": "本次调用最长等待秒数；MCP 客户端 HTTP 超时通常 120s，不要设超过 90",
					},
					"poll_interval_seconds": map[string]any{
						"type": "integer", "minimum": 1, "maximum": 10, "default": 2,
					},
				}, "task_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeTasksRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.waitTask(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "create_task",
				Title:       "创建扫描任务",
				Description: "创建扫描任务（pending 状态并入队，需再调用 start_task 才会执行）。写操作。targets 非空；type 建议使用 full / asset_discovery / port_scan / subdomain / fingerprint / vuln_scan / dir_scan / crawler / takeover。推荐链路：create_task → start_task → wait_task（超时就再调）→ get_task_results。",
				InputSchema: inputSchema(map[string]any{
					"project_id":   projectIDProp,
					"name":         map[string]any{"type": "string"},
					"description":  map[string]any{"type": "string"},
					"type":         map[string]any{"type": "string"},
					"targets":      map[string]any{"type": "array", "minItems": 1, "maxItems": 10000, "items": map[string]any{"type": "string"}},
					"target_type":  map[string]any{"type": "string", "enum": []string{"ip", "domain", "url", "cidr"}},
					"config":       map[string]any{"type": "object", "description": "TaskConfig，如 {scan_types, port_scan_mode, severity_filter}"},
					"is_scheduled": map[string]any{"type": "boolean", "default": false},
					"cron_expr":    map[string]any{"type": "string"},
					"tags":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				}, "name", "type", "targets", "target_type"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.createTask(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "update_task",
				Title:       "编辑任务",
				Description: "修改任务的可编辑字段（名称、描述、目标、配置、调度、标签）。写操作。",
				InputSchema: inputSchema(map[string]any{
					"task_id": taskIDProp,
					"updates": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"name":         map[string]any{"type": "string"},
							"description":  map[string]any{"type": "string"},
							"targets":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"target_type":  map[string]any{"type": "string"},
							"config":       map[string]any{"type": "object"},
							"is_scheduled": map[string]any{"type": "boolean"},
							"cron_expr":    map[string]any{"type": "string"},
							"tags":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						},
					},
				}, "task_id", "updates"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.updateTask(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "delete_task",
				Title:       "删除任务",
				Description: "删除任务；运行中的任务会先取消。破坏性操作。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.taskCommand(ctx, key, args, "delete")
			},
		},
		{
			Tool: mcpTool{
				Name:        "start_task",
				Title:       "启动任务",
				Description: "把 pending/paused 任务置为 running 并交给后台 worker 执行。会发起真实扫描。启动后用 wait_task 等待终态。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.taskCommand(ctx, key, args, "start")
			},
		},
		{
			Tool: mcpTool{
				Name:        "pause_task",
				Title:       "暂停任务",
				Description: "暂停运行中的任务。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.taskCommand(ctx, key, args, "pause")
			},
		},
		{
			Tool: mcpTool{
				Name:        "resume_task",
				Title:       "恢复任务",
				Description: "恢复暂停的任务并重新入队。会继续发起扫描。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.taskCommand(ctx, key, args, "resume")
			},
		},
		{
			Tool: mcpTool{
				Name:        "cancel_task",
				Title:       "取消任务",
				Description: "取消任务并丢弃排队作业。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.taskCommand(ctx, key, args, "cancel")
			},
		},
		{
			Tool: mcpTool{
				Name:        "retry_task",
				Title:       "重试任务",
				Description: "把 failed/cancelled 任务重置为 pending 并重新入队。会再次扫描。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.taskCommand(ctx, key, args, "retry")
			},
		},
		{
			Tool: mcpTool{
				Name:        "rescan_task",
				Title:       "续扫/重扫任务",
				Description: "对 completed/failed/cancelled 任务继续扫描或从头重扫（from_scratch=true 会重置进度与统计）。会再次扫描。",
				InputSchema: inputSchema(map[string]any{
					"task_id":      taskIDProp,
					"from_scratch": map[string]any{"type": "boolean", "default": false},
				}, "task_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeTasksWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.rescanTask(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_task_logs",
				Title:       "任务日志",
				Description: "分页读取任务执行日志。",
				InputSchema: inputSchema(map[string]any{
					"task_id":   taskIDProp,
					"page":      map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size": map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
				}, "task_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeTasksRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getTaskLogs(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_task_results",
				Title:       "任务结果",
				Description: "分页读取任务扫描结果，可按结果类型、关键字、状态码过滤。",
				InputSchema: inputSchema(map[string]any{
					"task_id":     taskIDProp,
					"result_type": resultTypeProp,
					"page":        map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size":   map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
					"search":      map[string]any{"type": "string"},
					"status_code": map[string]any{"type": "integer"},
				}, "task_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeTasksRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getTaskResults(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "get_task_result_stats",
				Title:       "任务结果统计",
				Description: "读取任务各结果类型的计数。",
				InputSchema: inputSchema(map[string]any{"task_id": taskIDProp}, "task_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeTasksRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.getTaskResultStats(ctx, key, args)
			},
		},
	}
}

func (s *MCPService) taskFor(ctx context.Context, key *repo.APIKey, taskID string) (*models.Task, error) {
	if strings.TrimSpace(taskID) == "" {
		return nil, errors.New("task_id 必填")
	}
	task, err := s.tasks.GetTaskByID(taskID)
	if err != nil {
		return nil, errors.New("任务不存在或不在该 API key 的授权范围内")
	}
	if task.ProjectID > 0 {
		if err := ensureProjectAllowed(key, task.ProjectID); err != nil {
			return nil, err
		}
	} else if key.ProjectID != nil {
		return nil, errors.New("任务不存在或不在该 API key 的授权范围内")
	}
	return task, nil
}

func (s *MCPService) listTasks(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID *int64 `json:"project_id"`
		Type      string `json:"type"`
		Status    string `json:"status"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := optionalProject(key, args.ProjectID)
	if err != nil {
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
	items, total, err := s.tasks.ListTasks("", args.Type, args.Status, projectID, args.Page, args.PageSize)
	if err != nil {
		return toolError("读取任务失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": total, "page": args.Page, "page_size": args.PageSize})
}

func (s *MCPService) getTask(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		TaskID string `json:"task_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	task, err := s.taskFor(ctx, key, args.TaskID)
	if err != nil {
		return toolError(err.Error())
	}
	return toolOK(task)
}

// waitTask 服务端轮询任务状态直到终态或本次调用超时。
// 平台 MCP 是无状态 JSON-RPC（无 SSE 推送），agent 感知任务完成只能靠它：
// 终态返回 finished=true；超时返回 finished=false + 当前进度，agent 再调一次即可续等。
// timeout_seconds 上限 90s：MCP 客户端的 HTTP 超时普遍是 120s，要留出余量。
func (s *MCPService) waitTask(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		TaskID          string `json:"task_id"`
		TimeoutSeconds  int    `json:"timeout_seconds"`
		PollIntervalSec int    `json:"poll_interval_seconds"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.TimeoutSeconds <= 0 {
		args.TimeoutSeconds = 30
	}
	if args.TimeoutSeconds > 90 {
		args.TimeoutSeconds = 90
	}
	if args.PollIntervalSec <= 0 {
		args.PollIntervalSec = 2
	}
	if args.PollIntervalSec > 10 {
		args.PollIntervalSec = 10
	}

	deadline := time.Now().Add(time.Duration(args.TimeoutSeconds) * time.Second)
	started := time.Now()
	for {
		task, err := s.taskFor(ctx, key, args.TaskID)
		if err != nil {
			return toolError(err.Error())
		}

		out := map[string]any{
			"task_id":        task.ID.Hex(),
			"status":         task.Status,
			"progress":       task.Progress,
			"waited_seconds": int(time.Since(started).Seconds()),
		}
		switch task.Status {
		case models.TaskStatusCompleted, models.TaskStatusFailed,
			models.TaskStatusCancelled, models.TaskStatusPaused:
			out["finished"] = true
			if task.Status == models.TaskStatusFailed && strings.TrimSpace(task.LastError) != "" {
				out["last_error"] = task.LastError
			}
			out["next"] = "用 get_task_results 读取结果"
			return toolOK(out)
		}

		if !time.Now().Before(deadline) || ctx.Err() != nil {
			out["finished"] = false
			out["next"] = "任务尚未到终态，请再次调用 wait_task 继续等待"
			return toolOK(out)
		}

		select {
		case <-ctx.Done():
			out["finished"] = false
			out["next"] = "调用被中断，请再次调用 wait_task 继续等待"
			return toolOK(out)
		case <-time.After(time.Duration(args.PollIntervalSec) * time.Second):
		}
	}
}

func (s *MCPService) createTask(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		ProjectID   *int64            `json:"project_id"`
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Type        models.TaskType   `json:"type"`
		Targets     []string          `json:"targets"`
		TargetType  string            `json:"target_type"`
		Config      models.TaskConfig `json:"config"`
		IsScheduled bool              `json:"is_scheduled"`
		CronExpr    string            `json:"cron_expr"`
		Tags        []string          `json:"tags"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	projectID, err := resolveKeyProject(key, args.ProjectID)
	if err != nil {
		return toolError(err.Error())
	}
	if strings.TrimSpace(args.Name) == "" {
		return toolError("name 必填")
	}
	if args.Type == "" {
		return toolError("type 必填")
	}
	if len(args.Targets) == 0 {
		return toolError("targets 不能为空")
	}
	if strings.TrimSpace(args.TargetType) == "" {
		return toolError("target_type 必填")
	}
	// 绑定项目的 key 与直接扫描走同一套目标归属校验，避免通过任务绕过。
	if err := s.ensureScanTargetsAllowed(ctx, key, args.Targets); err != nil {
		return toolError("任务目标校验失败: " + err.Error())
	}

	task := &models.Task{
		ProjectID: projectID, Name: args.Name, Description: args.Description,
		Type: args.Type, Targets: args.Targets, TargetType: args.TargetType,
		Config: args.Config, IsScheduled: args.IsScheduled, CronExpr: args.CronExpr,
		Tags: args.Tags,
	}
	task.ResultStats = models.TaskResultStats{TotalTargets: len(args.Targets)}
	if err := s.tasks.CreateTask(task); err != nil {
		return toolError("创建任务失败: " + err.Error())
	}
	return toolOK(map[string]any{
		"id": task.ID.Hex(), "project_id": projectID, "status": task.Status,
		"type": task.Type, "targets": len(args.Targets),
		"note": "任务已入队但尚未启动，调用 start_task 后才会执行",
	})
}

func (s *MCPService) updateTask(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		TaskID  string         `json:"task_id"`
		Updates map[string]any `json:"updates"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.taskFor(ctx, key, args.TaskID); err != nil {
		return toolError(err.Error())
	}
	allowed := map[string]bool{
		"name": true, "description": true, "targets": true, "target_type": true,
		"config": true, "is_scheduled": true, "cron_expr": true, "tags": true,
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
	if err := s.tasks.UpdateTask(args.TaskID, updates); err != nil {
		return toolError("更新任务失败: " + err.Error())
	}
	return toolOK(map[string]any{"task_id": args.TaskID, "updated": true})
}

func (s *MCPService) taskCommand(ctx context.Context, key *repo.APIKey, raw json.RawMessage, command string) *mcpToolResult {
	var args struct {
		TaskID string `json:"task_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.taskFor(ctx, key, args.TaskID); err != nil {
		return toolError(err.Error())
	}
	var err error
	switch command {
	case "delete":
		err = s.tasks.DeleteTask(args.TaskID)
	case "start":
		err = s.tasks.StartTask(args.TaskID)
	case "pause":
		err = s.tasks.PauseTask(args.TaskID)
	case "resume":
		err = s.tasks.ResumeTask(args.TaskID)
	case "cancel":
		err = s.tasks.CancelTask(args.TaskID)
	case "retry":
		err = s.tasks.RetryTask(args.TaskID)
	default:
		return toolError("未知任务操作")
	}
	if err != nil {
		return toolError("任务操作失败: " + err.Error())
	}
	return toolOK(map[string]any{"task_id": args.TaskID, "command": command, "ok": true})
}

func (s *MCPService) rescanTask(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		TaskID      string `json:"task_id"`
		FromScratch bool   `json:"from_scratch"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.taskFor(ctx, key, args.TaskID); err != nil {
		return toolError(err.Error())
	}
	if err := s.tasks.RescanTask(args.TaskID, args.FromScratch); err != nil {
		return toolError("续扫失败: " + err.Error())
	}
	return toolOK(map[string]any{"task_id": args.TaskID, "from_scratch": args.FromScratch, "ok": true})
}

func (s *MCPService) getTaskLogs(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		TaskID   string `json:"task_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.taskFor(ctx, key, args.TaskID); err != nil {
		return toolError(err.Error())
	}
	if args.Page <= 0 {
		args.Page = 1
	}
	if args.PageSize <= 0 {
		args.PageSize = 50
	}
	if args.PageSize > 200 {
		args.PageSize = 200
	}
	logs, total, err := s.tasks.GetTaskLogs(args.TaskID, args.Page, args.PageSize)
	if err != nil {
		return toolError("读取任务日志失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": logs, "total": total, "page": args.Page, "page_size": args.PageSize})
}

func (s *MCPService) getTaskResults(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		TaskID     string `json:"task_id"`
		ResultType string `json:"result_type"`
		Page       int    `json:"page"`
		PageSize   int    `json:"page_size"`
		Search     string `json:"search"`
		StatusCode int    `json:"status_code"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.taskFor(ctx, key, args.TaskID); err != nil {
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
	items, total, err := s.results.GetResultsByTask(args.TaskID, models.ResultType(args.ResultType),
		args.Page, args.PageSize, args.Search, args.StatusCode)
	if err != nil {
		return toolError("读取任务结果失败: " + err.Error())
	}
	return toolOK(map[string]any{"items": items, "total": total, "page": args.Page, "page_size": args.PageSize})
}

func (s *MCPService) getTaskResultStats(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	var args struct {
		TaskID string `json:"task_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if _, err := s.taskFor(ctx, key, args.TaskID); err != nil {
		return toolError(err.Error())
	}
	stats, err := s.results.GetResultStats(args.TaskID)
	if err != nil {
		return toolError("读取结果统计失败: " + err.Error())
	}
	return toolOK(stats)
}
