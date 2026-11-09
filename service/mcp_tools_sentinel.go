package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
)

// sentinelTools 是 CommitSentinel（代码审计）域工具。
//
// 面向「自带智能」的外部 agent：平台提供数据面（仓库/提交/diff/判定/发现）、
// 确定性验证面（pocsmith 沙箱差分复现，零 LLM），agent 自己读 diff、自己下结论，
// 经 sentinel_submit_judgment 回写——与平台内部 LLM 判定在 UNIQUE(commit_id, model)
// 下并存，归因 model=agent:<密钥名>。
// 消耗平台自身 LLM 的工具（judge_commit / generate_nuclei）额外要求 llm:invoke。
// 哨兵数据没有项目维度，与漏洞/POC 一致仅对「全部项目」的 key 开放。
// 人工闸门不动摇：confirmed / verified / publish 仍只在 Web UI 人工操作。
func (s *MCPService) sentinelTools() []mcpToolHandler {
	return []mcpToolHandler{
		{
			Tool: mcpTool{
				Name:        "sentinel_overview",
				Title:       "审计总览",
				Description: "代码审计（CommitSentinel）总览计数：纳管仓库、今日新提交、安全修复命中、待判定提交与队列积压。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(nil),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelOverview(ctx, key)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_list_repos",
				Title:       "列出审计仓库",
				Description: "列出纳管的监控仓库（full_name、分支、采集间隔、最近采集时间与错误）。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"keyword": map[string]any{"type": "string", "description": "按 owner/repo 关键字过滤"},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelListRepos(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_list_commits",
				Title: "列出提交",
				Description: "分页列出提交（不含 diff），可按仓库、SHA 前缀、状态（pending/judged/skipped/failed）、是否安全修复、时间过滤；" +
					"行内附带最新判定摘要。审计通常从 status=pending 开始。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"repo_id":      map[string]any{"type": "string"},
					"sha_prefix":   map[string]any{"type": "string"},
					"status":       map[string]any{"type": "string", "enum": []string{"pending", "judged", "skipped", "failed"}},
					"security_fix": map[string]any{"type": "boolean"},
					"since":        map[string]any{"type": "string", "description": "RFC3339"},
					"until":        map[string]any{"type": "string", "description": "RFC3339"},
					"page":         map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size":    map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelListCommits(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_get_commit",
				Title: "提交详情（审计输入）",
				Description: "读取一条提交的完整审计输入：元数据 + 完整 unified diff + 全部判定（内部模型与外部 agent 并列）+ 关联发现。" +
					"evidence 字段应引用 diff 中的 hunk 头（@@ -a,b +c,d @@），submit_judgment 会做匹配校验。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"commit_id":    map[string]any{"type": "integer", "minimum": 1, "description": "提交 ID（commit.id）"},
					"include_diff": map[string]any{"type": "boolean", "default": true, "description": "false 时省略 diff 只取元数据与结论"},
				}, "commit_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelGetCommit(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_list_findings",
				Title:       "列出发现",
				Description: "分页列出全部安全发现（跨仓库），可按状态（open/confirmed/ignored/resolved）、严重度、仓库过滤。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"status":    map[string]any{"type": "string", "enum": []string{"open", "confirmed", "ignored", "resolved"}},
					"severity":  map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}},
					"repo_id":   map[string]any{"type": "string"},
					"page":      map[string]any{"type": "integer", "minimum": 1, "default": 1},
					"page_size": map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelListFindings(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_get_finding",
				Title:       "发现详情",
				Description: "读取一条发现及其全部产物（PoC、nuclei 模板、repro-plan、复现日志；含内容）与机器复现标记。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"finding_id": map[string]any{"type": "integer", "minimum": 1},
				}, "finding_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelGetFinding(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_list_runs",
				Title:       "列出批次",
				Description: "列出采集/判定/复现批次（run）及状态与进度；配合 sentinel_get_run_events 回放过程。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"run_type": map[string]any{"type": "string", "enum": []string{"collect", "judge", "repro"}},
					"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
				}),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelListRuns(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_get_run_events",
				Title:       "批次事件",
				Description: "按 seq 增量读取批次事件流（repro_start / repro_verdict / judge_done / agent_submit 等），可反复调用跟进进度。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"run_id":    map[string]any{"type": "integer", "minimum": 1},
					"after_seq": map[string]any{"type": "integer", "minimum": 0, "default": 0},
					"limit":     map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 200},
				}, "run_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelGetRunEvents(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_wait_judge",
				Title: "等待判定",
				Description: "服务端轮询一条提交的判定进度，直到提交进入终态（judged/skipped/failed）或本次调用超时。" +
					"超时返回 finished=false，请再次调用。判定来源可能是平台模型或其它外部 agent，结果以判定列表为准。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"commit_id":             map[string]any{"type": "integer", "minimum": 1},
					"timeout_seconds":       map[string]any{"type": "integer", "minimum": 1, "maximum": 90, "default": 30},
					"poll_interval_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 10, "default": 2},
				}, "commit_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelWaitJudge(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_wait_repro",
				Title: "等待复现",
				Description: "服务端轮询一条发现的沙箱复现进度：finding 进入机器 verified、或产出 repro_log（verdict 已出）即返回。" +
					"材料缺失时复现会被跳过且不写 repro_log，超时后可用 sentinel_list_runs(run_type=repro) + sentinel_get_run_events 查看跳过原因。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"finding_id":            map[string]any{"type": "integer", "minimum": 1},
					"timeout_seconds":       map[string]any{"type": "integer", "minimum": 1, "maximum": 90, "default": 60},
					"poll_interval_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
				}, "finding_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelWaitRepro(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_list_skills",
				Title:       "审计技能目录",
				Description: "列出内置/自定义审计方法论清单（反序列化、越权、供应链等），按 sentinel_get_skill 取完整 prompt。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(nil),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelListSkills(ctx, key)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_get_skill",
				Title:       "审计技能详情",
				Description: "读取一份审计方法论的完整 prompt（检查清单），外部 agent 可按它执行同口径审计。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"skill_id": map[string]any{"type": "string", "description": "如 java-deser-audit"},
				}, "skill_id"),
				Annotations: readOnlyAnnotations(),
			},
			Scopes: []string{ScopeSentinelRead},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelGetSkill(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_create_repo",
				Title:       "纳管仓库",
				Description: "新增一个监控仓库（clone_url 需 https 且 host 在白名单内），创建后自动排一次采集。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"clone_url":        map[string]any{"type": "string", "description": "https://github.com/owner/repo.git"},
					"full_name":        map[string]any{"type": "string", "description": "owner/repo；留空则从 clone_url 推导"},
					"branch":           map[string]any{"type": "string", "description": "留空跟随默认分支"},
					"interval_minutes": map[string]any{"type": "integer", "minimum": 10, "default": 60},
				}, "clone_url"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelCreateRepo(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_delete_repo",
				Title:       "移除仓库",
				Description: "移除一个监控仓库（提交/判定/发现随级联删除）。破坏性操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"repo_id": map[string]any{"type": "string"},
				}, "repo_id"),
				Annotations: writeAnnotations(true),
			},
			Scopes: []string{ScopeSentinelWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelDeleteRepo(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_collect_repo",
				Title:       "立即采集",
				Description: "对一个纳管仓库立即排队增量采集（clone/fetch + 新提交入库，状态 pending）。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"repo_id": map[string]any{"type": "string"},
				}, "repo_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelCollectRepo(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_submit_judgment",
				Title: "提交外部判定",
				Description: "外部 agent 回写审计结论。服务端做同款校验：vuln_class/severity 枚举、evidence 与真实 hunk 头匹配" +
					"（不匹配则置信度减半并在结果中标注）。判定以 agent:<密钥名> 归因，与平台内部判定并存互不覆盖；" +
					"is_security_fix=true 时自动创建 open 状态的发现并通知。同一密钥对同一提交只允许一条（重复提交返回已有记录）。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"commit_id":         map[string]any{"type": "integer", "minimum": 1},
					"is_security_fix":   map[string]any{"type": "boolean"},
					"vuln_class":        map[string]any{"type": "string", "enum": SentinelVulnClasses},
					"severity":          map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}},
					"confidence":        map[string]any{"type": "number", "minimum": 0, "maximum": 1},
					"component":         map[string]any{"type": "string", "description": "受影响组件/标题；留空用 vuln_class"},
					"attack_path":       map[string]any{"type": "string", "description": "命中时必填：入口 → 传播 → 汇聚点，标注文件/函数"},
					"impact":            map[string]any{"type": "string", "description": "命中时必填：攻击者在什么条件下能造成什么后果"},
					"fix_evidence":      map[string]any{"type": "string", "description": "命中时必填：修复 diff 消除了攻击链哪一环"},
					"reasoning":         map[string]any{"type": "string"},
					"evidence":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "diff 中的 hunk 头（@@ ... @@）或其片段"},
					"evidence_snippets": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "命中时从 diff 原样摘录 2~4 段关键 +/- 代码行（逐字复制，逐字校验）"},
				}, "commit_id", "is_security_fix", "vuln_class", "severity", "confidence", "reasoning"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelSubmitJudgment(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_add_artifact",
				Title: "挂产物",
				Description: "为发现挂一份 draft 产物。kind=poc（PoC 脚本，标题可带 path=<容器内文件名>）；" +
					"kind=report 且 title=repro-plan 时 content 是 {vuln_image,fix_image,poc_path,poc_cmd} JSON（沙箱差分复现的构建计划）。" +
					"draft 需人工 verified 后才会进入复现与发布。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"finding_id": map[string]any{"type": "integer", "minimum": 1},
					"kind":       map[string]any{"type": "string", "enum": []string{"poc", "nuclei", "report", "patch"}},
					"title":      map[string]any{"type": "string"},
					"content":    map[string]any{"type": "string"},
				}, "finding_id", "kind", "title", "content"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelAddArtifact(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_request_repro",
				Title: "请求沙箱复现",
				Description: "把发现排入 pocsmith 差分复现队列（确定性执行，零 LLM：fix 镜像×1 + vuln 镜像×3 + 四条否决）。" +
					"前置材料：已人工 verified 的 poc 产物 + repro-plan。入队后用 sentinel_wait_repro 等结论。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"finding_id": map[string]any{"type": "integer", "minimum": 1},
				}, "finding_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelRequestRepro(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_judge_commit",
				Title:       "调用平台模型判定",
				Description: "把提交排入平台内部 LLM 判定队列（消耗平台模型额度，需要 llm:invoke 权限）。入队后用 sentinel_wait_judge 等结果。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"commit_id": map[string]any{"type": "integer", "minimum": 1},
				}, "commit_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite, ScopeLLMInvoke},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelJudgeCommit(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:        "sentinel_generate_nuclei",
				Title:       "生成 nuclei 模板",
				Description: "用平台模型把安全修复 diff 转化为 nuclei POC 模板草稿（消耗平台模型额度，需要 llm:invoke 权限）；草稿仍需人工 verified。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"finding_id": map[string]any{"type": "integer", "minimum": 1},
				}, "finding_id"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite, ScopeLLMInvoke},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelGenerateNuclei(ctx, key, args)
			},
		},
		{
			Tool: mcpTool{
				Name:  "sentinel_import_archive",
				Title: "上传代码包分析",
				Description: "上传 zip/tar.gz 代码压缩包（base64，≤3MB）导入为本地静态仓库：解包 → 建 mirror → 采集落库提交 → 自动入队判定。" +
					"包含 .git 的包按提交历史逐提交判定；纯源码包会合成单条初始提交。导入后用 sentinel_list_commits(repo_id) 查看新提交，" +
					"按工作流分析（或 sentinel_wait_judge 等平台判定）。写操作。仅「全部项目」的 key 可用。",
				InputSchema: inputSchema(map[string]any{
					"name":           map[string]any{"type": "string", "description": "仓库名（展示用，可含中文）"},
					"filename":       map[string]any{"type": "string", "description": "压缩包文件名，需以 .zip/.tar.gz/.tgz 结尾"},
					"content_base64": map[string]any{"type": "string", "description": "压缩包内容的 base64 编码"},
				}, "name", "filename", "content_base64"),
				Annotations: writeAnnotations(false),
			},
			Scopes: []string{ScopeSentinelWrite},
			Run: func(ctx context.Context, key *repo.APIKey, args json.RawMessage) *mcpToolResult {
				return s.sentinelImportArchive(ctx, key, args)
			},
		},
	}
}

// sentinelStore 取哨兵数据层；无 DB 的单测路径返回错误。
func sentinelStore() (*repo.Sentinel, error) {
	r := repo.Default()
	if r == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	return r.Sentinel(), nil
}

func (s *MCPService) sentinelOverview(ctx context.Context, key *repo.APIKey) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	ov, err := store.Overview(ctx, []string{SentinelCollectQueueName, SentinelJudgeQueueName})
	if err != nil {
		return toolError("读取审计总览失败: " + err.Error())
	}
	return toolOK(ov)
}

func (s *MCPService) sentinelListRepos(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		Keyword string `json:"keyword"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	items, err := store.ListRepos(ctx, strings.TrimSpace(args.Keyword))
	if err != nil {
		return toolError("读取仓库列表失败: " + err.Error())
	}
	if items == nil {
		items = []*repo.GitRepo{}
	}
	return toolOK(map[string]any{"items": items, "total": len(items)})
}

func (s *MCPService) sentinelListCommits(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		RepoID      string `json:"repo_id"`
		SHAPrefix   string `json:"sha_prefix"`
		Status      string `json:"status"`
		SecurityFix *bool  `json:"security_fix"`
		Since       string `json:"since"`
		Until       string `json:"until"`
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
		args.PageSize = 20
	}
	if args.PageSize > 100 {
		args.PageSize = 100
	}
	f := repo.CommitFilter{
		RepoID: strings.TrimSpace(args.RepoID),
		SHA:    strings.TrimSpace(args.SHAPrefix),
		Status: strings.TrimSpace(args.Status),
		Page:   args.Page,
		Size:   args.PageSize,
	}
	if args.SecurityFix != nil {
		f.OnlySecurityFix = *args.SecurityFix
	}
	for field, rawTS := range map[string]string{"since": args.Since, "until": args.Until} {
		if strings.TrimSpace(rawTS) == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(rawTS))
		if err != nil {
			return toolError(field + " 需要 RFC3339 格式")
		}
		if field == "since" {
			f.Since = &t
		} else {
			f.Until = &t
		}
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	items, total, err := store.ListCommits(ctx, f)
	if err != nil {
		return toolError("读取提交列表失败: " + err.Error())
	}
	if items == nil {
		items = []*repo.CommitListItem{}
	}
	return toolOK(map[string]any{"items": items, "total": total, "page": args.Page, "page_size": args.PageSize})
}

func (s *MCPService) sentinelGetCommit(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		CommitID    int64 `json:"commit_id"`
		IncludeDiff *bool `json:"include_diff"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.CommitID <= 0 {
		return toolError("commit_id 必填")
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	commit, err := store.GetCommit(ctx, args.CommitID)
	if err != nil {
		return toolError("提交不存在: " + err.Error())
	}
	includeDiff := args.IncludeDiff == nil || *args.IncludeDiff
	if !includeDiff {
		commit.Diff = ""
	}
	judgments, _ := store.ListJudgmentsByCommit(ctx, args.CommitID)
	if judgments == nil {
		judgments = []*repo.CommitJudgment{}
	}
	findings, _ := store.ListFindingsByCommit(ctx, args.CommitID)
	if findings == nil {
		findings = []*repo.CommitFinding{}
	}
	return toolOK(map[string]any{
		"commit": commit, "judgments": judgments, "findings": findings,
		"note": "evidence 建议引用 diff 的 hunk 头（@@ ... @@），submit_judgment 会做匹配校验",
	})
}

func (s *MCPService) sentinelListFindings(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		Status   string `json:"status"`
		Severity string `json:"severity"`
		RepoID   string `json:"repo_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
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
	if args.PageSize > 200 {
		args.PageSize = 200
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	items, total, err := store.ListFindings(ctx, repo.FindingFilter{
		Status: strings.TrimSpace(args.Status), Severity: strings.TrimSpace(args.Severity),
		RepoID: strings.TrimSpace(args.RepoID), Page: args.Page, Size: args.PageSize,
	})
	if err != nil {
		return toolError("读取发现列表失败: " + err.Error())
	}
	if items == nil {
		items = []*repo.FindingListItem{}
	}
	return toolOK(map[string]any{"items": items, "total": total, "page": args.Page, "page_size": args.PageSize})
}

func (s *MCPService) sentinelGetFinding(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.FindingID <= 0 {
		return toolError("finding_id 必填")
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	finding, err := store.GetFinding(ctx, args.FindingID)
	if err != nil {
		return toolError("发现不存在: " + err.Error())
	}
	artifacts, _ := store.ListArtifacts(ctx, args.FindingID)
	if artifacts == nil {
		artifacts = []*repo.CommitArtifact{}
	}
	return toolOK(map[string]any{"finding": finding, "artifacts": artifacts})
}

func (s *MCPService) sentinelListRuns(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		RunType string `json:"run_type"`
		Limit   int    `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.Limit <= 0 {
		args.Limit = 20
	}
	if args.Limit > 100 {
		args.Limit = 100
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	items, err := store.ListRuns(ctx, strings.TrimSpace(args.RunType), args.Limit)
	if err != nil {
		return toolError("读取批次列表失败: " + err.Error())
	}
	if items == nil {
		items = []*repo.SentinelRun{}
	}
	return toolOK(map[string]any{"items": items, "total": len(items), "limit": args.Limit})
}

func (s *MCPService) sentinelGetRunEvents(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		RunID    int64 `json:"run_id"`
		AfterSeq int64 `json:"after_seq"`
		Limit    int   `json:"limit"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.RunID <= 0 {
		return toolError("run_id 必填")
	}
	if args.Limit <= 0 {
		args.Limit = 200
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	events, err := store.EventsAfter(ctx, args.RunID, args.AfterSeq, args.Limit)
	if err != nil {
		return toolError("读取批次事件失败: " + err.Error())
	}
	if events == nil {
		events = []*repo.SentinelRunEvent{}
	}
	var nextAfter int64 = args.AfterSeq
	if n := len(events); n > 0 {
		nextAfter = events[n-1].Seq
	}
	return toolOK(map[string]any{"items": events, "next_after_seq": nextAfter})
}

// sentinelWaitArgs 是两个 wait 工具的公共参数（上限对齐 wait_task：MCP 客户端 ~120s 超时）。
type sentinelWaitArgs struct {
	TimeoutSeconds     int `json:"timeout_seconds"`
	PollIntervalSecond int `json:"poll_interval_seconds"`
}

func (a *sentinelWaitArgs) normalize(defaultTimeout, defaultPoll int) {
	if a.TimeoutSeconds <= 0 {
		a.TimeoutSeconds = defaultTimeout
	}
	if a.TimeoutSeconds > 90 {
		a.TimeoutSeconds = 90
	}
	if a.PollIntervalSecond <= 0 {
		a.PollIntervalSecond = defaultPoll
	}
	if a.PollIntervalSecond > 10 {
		a.PollIntervalSecond = 10
	}
}

func (s *MCPService) sentinelWaitJudge(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		CommitID int64 `json:"commit_id"`
		sentinelWaitArgs
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.CommitID <= 0 {
		return toolError("commit_id 必填")
	}
	args.sentinelWaitArgs.normalize(30, 2)

	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	deadline := time.Now().Add(time.Duration(args.TimeoutSeconds) * time.Second)
	started := time.Now()
	for {
		commit, err := store.GetCommit(ctx, args.CommitID)
		if err != nil {
			return toolError("提交不存在: " + err.Error())
		}
		out := map[string]any{
			"commit_id": commit.ID, "status": commit.Status,
			"waited_seconds": int(time.Since(started).Seconds()),
		}
		switch commit.Status {
		case "judged", "skipped", "failed":
			judgments, _ := store.ListJudgmentsByCommit(ctx, args.CommitID)
			out["finished"] = true
			out["judgments"] = judgments
			out["next"] = "判定已出，详见 judgments"
			return toolOK(out)
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			out["finished"] = false
			out["next"] = "提交尚未到终态，请再次调用 sentinel_wait_judge 继续等待"
			return toolOK(out)
		}
		select {
		case <-ctx.Done():
			out["finished"] = false
			out["next"] = "调用被中断，请再次调用 sentinel_wait_judge 继续等待"
			return toolOK(out)
		case <-time.After(time.Duration(args.PollIntervalSecond) * time.Second):
		}
	}
}

func (s *MCPService) sentinelWaitRepro(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		FindingID int64 `json:"finding_id"`
		sentinelWaitArgs
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.FindingID <= 0 {
		return toolError("finding_id 必填")
	}
	args.sentinelWaitArgs.normalize(60, 3)

	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	deadline := time.Now().Add(time.Duration(args.TimeoutSeconds) * time.Second)
	started := time.Now()
	for {
		f, err := store.GetFinding(ctx, args.FindingID)
		if err != nil {
			return toolError("发现不存在: " + err.Error())
		}
		out := map[string]any{
			"finding_id": f.ID, "status": f.Status,
			"verified":       f.VerifiedAt != nil,
			"waited_seconds": int(time.Since(started).Seconds()),
		}
		// verdict 落地即返回：通过 → verified_at；未通过 → repro_log 产物（title 携带 veto）。
		if f.VerifiedAt != nil {
			out["finished"] = true
			out["verdict"] = "passed（differential-ok）"
			out["next"] = "复现通过，等待人工 confirmed 收尾"
			return toolOK(out)
		}
		artifacts, _ := store.ListArtifacts(ctx, args.FindingID)
		for _, a := range artifacts {
			if a.Kind == "repro_log" {
				out["finished"] = true
				out["verdict"] = strings.TrimPrefix(a.Title, "repro: ")
				out["repro_log_artifact_id"] = a.ID
				out["next"] = "复现未通过或被否决，详见 repro_log 产物（sentinel_get_finding）"
				return toolOK(out)
			}
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			out["finished"] = false
			out["next"] = "尚未见结论：材料缺失会被跳过且不写 repro_log，用 sentinel_list_runs(run_type=repro) 排查"
			return toolOK(out)
		}
		select {
		case <-ctx.Done():
			out["finished"] = false
			out["next"] = "调用被中断，请再次调用 sentinel_wait_repro 继续等待"
			return toolOK(out)
		case <-time.After(time.Duration(args.PollIntervalSecond) * time.Second):
		}
	}
}

func (s *MCPService) sentinelListSkills(ctx context.Context, key *repo.APIKey) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	return toolOK(map[string]any{"items": SentinelSkillCatalogCtx(ctx)})
}

func (s *MCPService) sentinelGetSkill(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		SkillID string `json:"skill_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	skill, ok := FindSentinelSkill(strings.TrimSpace(args.SkillID))
	if !ok {
		return toolError("技能不存在或已停用: " + args.SkillID)
	}
	return toolOK(skill)
}

func (s *MCPService) sentinelCreateRepo(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		CloneURL        string `json:"clone_url"`
		FullName        string `json:"full_name"`
		Branch          string `json:"branch"`
		IntervalMinutes int    `json:"interval_minutes"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	cfg := config.Loaded()
	if cfg == nil {
		return toolError("配置未加载")
	}
	cloneURL, err := ValidateCloneURL(args.CloneURL, cfg.Sentinel.CloneHosts)
	if err != nil {
		return toolError(err.Error())
	}
	fullName := strings.TrimSpace(args.FullName)
	if fullName == "" {
		fullName = sentinelDeriveFullName(cloneURL)
	}
	if strings.Count(fullName, "/") != 1 {
		return toolError("full_name 需要是 owner/repo 形式")
	}
	interval := args.IntervalMinutes
	if interval < 10 {
		interval = 60
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	item := &repo.GitRepo{
		ID:              oid.NewObjectID().Hex(),
		FullName:        fullName,
		CloneURL:        cloneURL,
		DefaultBranch:   "main",
		Branch:          strings.TrimSpace(args.Branch),
		IntervalMinutes: interval,
		Enabled:         true,
	}
	if err := store.CreateRepo(ctx, item); err != nil {
		if err == repo.ErrDuplicate {
			return toolError("该仓库已存在")
		}
		return toolError("新增仓库失败: " + err.Error())
	}
	// 新建即排队一次采集，外部 agent 不必等调度周期。
	if q := DefaultSentinelQueue(); q != nil {
		if err := q.EnqueueCollect(ctx, item.ID); err != nil {
			return toolOK(map[string]any{"repo": item, "note": "仓库已创建，但采集入队失败: " + err.Error()})
		}
	}
	return toolOK(map[string]any{"repo": item, "next": "采集已排队，稍后用 sentinel_list_commits(repo_id) 查看新提交"})
}

// sentinelDeriveFullName 从 https clone url 推导 owner/repo（与 HTTP 侧 deriveFullName 同规则）。
func sentinelDeriveFullName(cloneURL string) string {
	u, err := url.Parse(cloneURL)
	if err != nil {
		return ""
	}
	path := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}

func (s *MCPService) sentinelDeleteRepo(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		RepoID string `json:"repo_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if strings.TrimSpace(args.RepoID) == "" {
		return toolError("repo_id 必填")
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	if _, err := store.GetRepo(ctx, strings.TrimSpace(args.RepoID)); err != nil {
		return toolError("仓库不存在: " + err.Error())
	}
	if err := store.DeleteRepo(ctx, strings.TrimSpace(args.RepoID)); err != nil {
		return toolError("删除仓库失败: " + err.Error())
	}
	return toolOK(map[string]any{"repo_id": args.RepoID, "deleted": true})
}

func (s *MCPService) sentinelCollectRepo(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		RepoID string `json:"repo_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	repoID := strings.TrimSpace(args.RepoID)
	if repoID == "" {
		return toolError("repo_id 必填")
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	if _, err := store.GetRepo(ctx, repoID); err != nil {
		return toolError("仓库不存在: " + err.Error())
	}
	q := DefaultSentinelQueue()
	if q == nil {
		return toolError("提交哨兵未启用（sentinel.enabled=false）")
	}
	if err := q.EnqueueCollect(ctx, repoID); err != nil {
		return toolError("采集入队失败: " + err.Error())
	}
	return toolOK(map[string]any{"repo_id": repoID, "enqueued": true,
		"next": "用 sentinel_list_commits(repo_id, status=pending) 或 sentinel_list_runs(run_type=collect) 跟进"})
}

// sentinelSubmitJudgment 是外部 agent 回写审计结论的入口：
// 校验与内部判定同源（decodeJudgeVerdict + applyEvidenceCheck），
// 归因 model=agent:<keyname>，命中安全修复自动建 finding 并通知。
func (s *MCPService) sentinelSubmitJudgment(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		CommitID         int64    `json:"commit_id"`
		IsSecurityFix    bool     `json:"is_security_fix"`
		VulnClass        string   `json:"vuln_class"`
		Severity         string   `json:"severity"`
		Confidence       float64  `json:"confidence"`
		Component        string   `json:"component"`
		AttackPath       string   `json:"attack_path"`
		Impact           string   `json:"impact"`
		FixEvidence      string   `json:"fix_evidence"`
		Reasoning        string   `json:"reasoning"`
		Evidence         []string `json:"evidence"`
		EvidenceSnippets []string `json:"evidence_snippets"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.CommitID <= 0 {
		return toolError("commit_id 必填")
	}
	if strings.TrimSpace(args.Reasoning) == "" {
		return toolError("reasoning 必填：外部判定必须给出分析过程")
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	commit, err := store.GetCommit(ctx, args.CommitID)
	if err != nil {
		return toolError("提交不存在: " + err.Error())
	}
	// 复用内部判定的解析/归一化（枚举校验、confidence 夹取、默认值），保证两路口径一致。
	verdictRaw, _ := json.Marshal(map[string]any{
		"is_security_fix":   args.IsSecurityFix,
		"vuln_class":        args.VulnClass,
		"confidence":        args.Confidence,
		"severity":          args.Severity,
		"component":         args.Component,
		"attack_path":       args.AttackPath,
		"impact":            args.Impact,
		"fix_evidence":      args.FixEvidence,
		"reasoning":         args.Reasoning,
		"evidence":          args.Evidence,
		"evidence_snippets": args.EvidenceSnippets,
	})
	verdict, err := decodeJudgeVerdict(string(verdictRaw))
	if err != nil {
		return toolError("判定参数不合法: " + err.Error())
	}
	// 内部模型靠 prompt 纪律给三段式；外部 agent 是程序化构造参数，直接硬校验，
	// 保证外部判定与内部判定同数据质量。
	if verdict.IsSecurityFix {
		missing := make([]string, 0, 3)
		if verdict.AttackPath == "" {
			missing = append(missing, "attack_path")
		}
		if verdict.Impact == "" {
			missing = append(missing, "impact")
		}
		if verdict.FixEvidence == "" {
			missing = append(missing, "fix_evidence")
		}
		if len(missing) > 0 {
			return toolError("is_security_fix=true 时必须完整给出: " + strings.Join(missing, " / "))
		}
	}
	confidenceBefore := verdict.Confidence
	files := ParseDiff(commit.Diff)
	verdict = applyEvidenceCheck(verdict, HunkHeaders(files), DiffLines(files))
	evidenceMatched := verdict.Confidence >= confidenceBefore || !verdict.IsSecurityFix

	model := "agent:" + key.Name
	judgment := &repo.CommitJudgment{
		CommitID:      commit.ID,
		Model:         model,
		IsSecurityFix: verdict.IsSecurityFix,
		VulnClass:     verdict.VulnClass,
		Severity:      verdict.Severity,
		Confidence:    verdict.Confidence,
		Title:         verdict.Title,
		Reasoning:     verdict.Reasoning,
		AttackPath:    verdict.AttackPath,
		Impact:        verdict.Impact,
		FixEvidence:   verdict.FixEvidence,
		Partial:       false,
	}
	evidenceJSON, _ := json.Marshal(verdict.Evidence)
	judgment.Evidence = evidenceJSON
	snippetsJSON, _ := json.Marshal(verdict.Snippets)
	judgment.Snippets = snippetsJSON

	id, inserted, err := store.InsertJudgment(ctx, judgment)
	if err != nil {
		return toolError("判定落库失败: " + err.Error())
	}
	if !inserted {
		existing, gerr := store.GetJudgmentByModel(ctx, commit.ID, model)
		if gerr != nil {
			return toolError("该密钥对此提交已有判定（并发重复）")
		}
		return toolOK(map[string]any{"inserted": false, "judgment": existing,
			"note": "同一密钥对同一提交只允许一条判定，以上为已有记录"})
	}
	judgment.ID = id

	if commit.Status == "pending" {
		if err := store.MarkCommitStatus(ctx, commit.ID, "judged", ""); err != nil {
			return toolOK(map[string]any{"inserted": true, "judgment": judgment,
				"note": "判定已落库，但更新提交状态失败: " + err.Error(), "evidence_matched": evidenceMatched})
		}
	}
	var findingID int64
	if verdict.IsSecurityFix {
		findingID, _ = store.CreateFinding(ctx, &repo.CommitFinding{
			CommitID:   commit.ID,
			JudgmentID: &judgment.ID,
			VulnClass:  verdict.VulnClass,
			Severity:   verdict.Severity,
			Status:     "open",
			Title:      verdict.Title,
			Detail:     verdict.Reasoning,
		})
		notifyJudgeHit(commit, verdict, judgment.ID)
	}
	// 与内部判定同款批次化：前端批次视图可见 agent 提交轨迹。
	if runID, rerr := store.CreateRun(ctx, &repo.SentinelRun{
		RunType: "judge", RepoID: &commit.RepoID, Status: "running", Total: 1,
	}); rerr == nil {
		payload, _ := json.Marshal(map[string]any{
			"agent": key.Name, "is_security_fix": verdict.IsSecurityFix,
			"vuln_class": verdict.VulnClass, "severity": verdict.Severity,
		})
		_, _ = store.AppendRunEvent(ctx, &repo.SentinelRunEvent{
			RunID: runID, Level: "info", Kind: "agent_submit",
			Message: fmt.Sprintf("外部 agent 判定: %s（%s/%s）", key.Name, verdict.VulnClass, verdict.Severity),
			Payload: payload,
		})
		_ = store.UpdateRun(ctx, runID, map[string]interface{}{
			"status": "completed", "processed": 1, "finished_at": time.Now(),
		})
	}

	out := map[string]any{
		"inserted": true, "judgment": judgment, "evidence_matched": evidenceMatched,
	}
	if verdict.IsSecurityFix {
		out["finding_id"] = findingID
		out["next"] = "已创建 open 发现；可 add_artifact 挂 PoC 与 repro-plan，verified 后 request_repro"
	}
	if !evidenceMatched {
		out["evidence_note"] = "evidence 未匹配真实 hunk 头，置信度已减半；请引用 @@ ... @@ 形式的 hunk 头重新提交一次可撤销打折"
	}
	return toolOK(out)
}

func (s *MCPService) sentinelAddArtifact(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		FindingID int64  `json:"finding_id"`
		Kind      string `json:"kind"`
		Title     string `json:"title"`
		Content   string `json:"content"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.FindingID <= 0 {
		return toolError("finding_id 必填")
	}
	artifact, err := AddFindingArtifact(ctx, args.FindingID, args.Kind, args.Title, args.Content)
	if err != nil {
		return toolError("挂产物失败: " + err.Error())
	}
	return toolOK(map[string]any{"artifact": artifact,
		"note": "产物为 draft；人工 verified 后才可进入复现与发布（人工闸门）"})
}

func (s *MCPService) sentinelRequestRepro(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.FindingID <= 0 {
		return toolError("finding_id 必填")
	}
	q := DefaultSentinelQueue()
	if q == nil {
		return toolError("提交哨兵未启用（sentinel.enabled=false）")
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	f, err := store.GetFinding(ctx, args.FindingID)
	if err != nil {
		return toolError("发现不存在: " + err.Error())
	}
	if f.VerifiedAt != nil {
		return toolOK(map[string]any{"finding_id": args.FindingID, "skipped": true,
			"note": "机器复现已通过（verified_at 非空），永不重复复现"})
	}
	// 入队前先做材料预检（与 pocsmith loadMaterials 同口径），把可修复的缺失顶到调用方。
	if _, _, plan, lerr := NewReproService("", 0).loadMaterials(ctx, args.FindingID); lerr != nil {
		return toolError("复现材料不齐: " + lerr.Error())
	} else if plan == nil {
		return toolError("复现材料不齐：缺少 title=repro-plan 的产物（JSON：vuln_image/fix_image/poc_path/poc_cmd）")
	}
	if err := q.EnqueueRepro(ctx, args.FindingID); err != nil {
		return toolError("复现入队失败: " + err.Error())
	}
	return toolOK(map[string]any{"finding_id": args.FindingID, "enqueued": true,
		"next": "用 sentinel_wait_repro(finding_id) 等差分结论（需 pocsmith 进程在运行）"})
}

// sentinelLLMReady 在动平台模型额度前做廉价预检（构造客户端不发请求），
// 未配置时给出可操作的错误，而不是烧一次队列往返。
func sentinelLLMReady(ctx context.Context) error {
	cfg := config.Loaded()
	if cfg == nil {
		return fmt.Errorf("配置未加载")
	}
	eff := EffectiveLLMConfig(ctx, cfg.LLM)
	if _, err := llm.NewJSONChatModel(ctx, eff); err != nil {
		return fmt.Errorf("平台模型未配置（管理后台 → 设置 → 模型接入）: %w", err)
	}
	return nil
}

func (s *MCPService) sentinelJudgeCommit(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		CommitID int64 `json:"commit_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.CommitID <= 0 {
		return toolError("commit_id 必填")
	}
	if err := sentinelLLMReady(ctx); err != nil {
		return toolError(err.Error())
	}
	store, err := sentinelStore()
	if err != nil {
		return toolError(err.Error())
	}
	if _, err := store.GetCommit(ctx, args.CommitID); err != nil {
		return toolError("提交不存在: " + err.Error())
	}
	q := DefaultSentinelQueue()
	if q == nil {
		return toolError("提交哨兵未启用（sentinel.enabled=false）")
	}
	if err := q.EnqueueJudge(ctx, args.CommitID); err != nil {
		return toolError("判定入队失败: " + err.Error())
	}
	return toolOK(map[string]any{"commit_id": args.CommitID, "enqueued": true,
		"next": "用 sentinel_wait_judge(commit_id) 等判定结果（判定以模型名幂等，已判过会直接返回已有记录）"})
}

func (s *MCPService) sentinelGenerateNuclei(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	if args.FindingID <= 0 {
		return toolError("finding_id 必填")
	}
	if err := sentinelLLMReady(ctx); err != nil {
		return toolError(err.Error())
	}
	artifact, err := GenerateNucleiTemplate(ctx, args.FindingID)
	if err != nil {
		return toolError("生成 nuclei 模板失败: " + err.Error())
	}
	return toolOK(map[string]any{"artifact": artifact,
		"note": "模板为 draft，人工 verified 后可发布进 PoC 库"})
}

// sentinelImportArchive 是 Agent 上传代码包分析的入口：base64 压缩包 →
// 解包建仓 → 采集落库 → 判定入队。MCP 请求体 4MiB，base64 有效载荷卡 3MB，
// 更大的包走 REST POST /api/sentinel/repos/import-archive（32MB multipart）。
func (s *MCPService) sentinelImportArchive(ctx context.Context, key *repo.APIKey, raw json.RawMessage) *mcpToolResult {
	if err := requireGlobalKey(key); err != nil {
		return toolError(err.Error())
	}
	var args struct {
		Name          string `json:"name"`
		Filename      string `json:"filename"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return toolError(err.Error())
	}
	content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args.ContentBase64))
	if err != nil {
		return toolError("content_base64 不是合法 base64: " + err.Error())
	}
	cfg := config.Loaded()
	if cfg == nil {
		return toolError("配置未加载")
	}
	src := NewSentinelSource(cfg.Sentinel)
	res, err := src.ImportArchive(ctx, args.Name, args.Filename, content)
	if err != nil {
		return toolError("导入失败: " + err.Error())
	}
	out := map[string]any{"result": res}
	if res.Error != "" {
		out["note"] = "仓库已注册，但采集失败，可稍后用 sentinel_collect_repo 重试"
	} else {
		out["next"] = "用 sentinel_list_commits(repo_id, status=pending) 查看新提交并按工作流分析；" +
			"纯源码包是合成单提交，判定以「整包初检」视角进行"
	}
	return toolOK(out)
}
