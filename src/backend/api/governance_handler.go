package api

import (
	"errors"
	"strconv"
	"strings"

	reconkitfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// GovernanceHandler 是资产治理域「周期」部分的 HTTP 入口：
// 种子 → 计划 → 批次 → 执行单元。
type GovernanceHandler struct {
	cycles    *service.CycleService
	probes    *service.ProbeExecutor
	verify    *service.VerifyService
	cleanup   *service.CleanupService
	fp        *service.FingerprintService
	fpSync    *service.FingerprintSyncService
	relations *service.RelationService
	replay    *service.ReplayService
}

func NewGovernanceHandler() *GovernanceHandler {
	return &GovernanceHandler{
		cycles:    service.NewCycleService(),
		probes:    service.NewProbeExecutor(8),
		verify:    service.NewVerifyService(),
		cleanup:   service.NewCleanupService(),
		fp:        service.NewFingerprintService(),
		fpSync:    service.NewFingerprintSyncService(),
		relations: service.NewRelationService(),
		replay:    service.NewReplayService(),
	}
}

func (h *GovernanceHandler) stores() (repo.SeedRepo, repo.RunRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, nil, errors.New("数据层未初始化")
	}
	return r.Seeds(), r.Runs(), nil
}

// ListSeeds 列出种子。GET /api/seeds?project_id=
func (h *GovernanceHandler) ListSeeds(c *gin.Context) {
	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	list, err := seeds.ListSeeds(c.Request.Context(), projectID)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, list)
}

// PreviewSeed 预览种子展开结果：不落库、不向目标发请求。
// POST /api/seeds/preview
func (h *GovernanceHandler) PreviewSeed(c *gin.Context) {
	var body service.SeedPreviewRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.cycles.PreviewSeed(c.Request.Context(), body)
	if err != nil {
		if errors.Is(err, service.ErrSeedValidation) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, res)
}

// CreateSeed 新建种子。POST /api/seeds
func (h *GovernanceHandler) CreateSeed(c *gin.Context) {
	var body struct {
		ProjectID  int64          `json:"project_id" binding:"required"`
		Kind       string         `json:"kind" binding:"required"`
		Value      string         `json:"value" binding:"required"`
		Capability map[string]any `json:"capability"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	switch body.Kind {
	case "domain", "cidr", "company", "cert", "repo", "app", "dict":
	default:
		utils.BadRequest(c, "kind 只支持 domain / cidr / company / cert / repo / app / dict")
		return
	}

	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	seed := &repo.Seed{
		ProjectID:  body.ProjectID,
		Kind:       body.Kind,
		Value:      body.Value,
		Capability: body.Capability,
		Enabled:    true,
	}
	if err := seeds.CreateSeed(c.Request.Context(), seed); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "创建成功", seed)
}

// DeleteSeed 删除种子（计划随之级联删除）。DELETE /api/seeds/:id
func (h *GovernanceHandler) DeleteSeed(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法种子 ID")
		return
	}
	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if err := seeds.DeleteSeed(c.Request.Context(), id); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "种子不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// ListPlans 列出计划。GET /api/plans?project_id=
func (h *GovernanceHandler) ListPlans(c *gin.Context) {
	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	list, err := seeds.ListPlans(c.Request.Context(), projectID)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, list)
}

// CreatePlan 新建计划。POST /api/plans
func (h *GovernanceHandler) CreatePlan(c *gin.Context) {
	var body struct {
		SeedID        int64          `json:"seed_id" binding:"required"`
		IntervalHours int            `json:"interval_hours"`
		Budget        map[string]any `json:"budget"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if body.IntervalHours == 0 {
		body.IntervalHours = 24
	}
	if body.IntervalHours < 1 || body.IntervalHours > 720 {
		utils.BadRequest(c, "interval_hours 需在 1..720")
		return
	}

	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	plan := &repo.Plan{SeedID: body.SeedID, IntervalHours: body.IntervalHours, Budget: body.Budget, Enabled: true}
	if err := seeds.CreatePlan(c.Request.Context(), plan); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "创建成功，已标记为立即到期", plan)
}

// UpdatePlan 启停 / 改间隔。PUT /api/plans/:id
func (h *GovernanceHandler) UpdatePlan(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法计划 ID")
		return
	}
	var body struct {
		Enabled       *bool   `json:"enabled"`
		IntervalHours *int    `json:"interval_hours"`
		TriggerMode   *string `json:"trigger_mode"`
		CooldownMin   *int    `json:"change_cooldown_minutes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if body.IntervalHours != nil && (*body.IntervalHours < 1 || *body.IntervalHours > 720) {
		utils.BadRequest(c, "interval_hours 需在 1..720")
		return
	}
	if body.TriggerMode != nil {
		switch strings.ToLower(strings.TrimSpace(*body.TriggerMode)) {
		case repo.PlanTriggerInterval, repo.PlanTriggerOnChange, repo.PlanTriggerBoth:
			*body.TriggerMode = strings.ToLower(strings.TrimSpace(*body.TriggerMode))
		default:
			utils.BadRequest(c, "trigger_mode 只支持 interval / on_change / both")
			return
		}
	}
	if body.CooldownMin != nil && (*body.CooldownMin < 1 || *body.CooldownMin > 1440) {
		utils.BadRequest(c, "change_cooldown_minutes 需在 1..1440")
		return
	}

	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if err := seeds.UpdatePlan(c.Request.Context(), id, body.Enabled, body.IntervalHours, body.TriggerMode, body.CooldownMin); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "计划不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeletePlan 删除计划。DELETE /api/plans/:id
func (h *GovernanceHandler) DeletePlan(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法计划 ID")
		return
	}
	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if err := seeds.DeletePlan(c.Request.Context(), id); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "计划不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// TriggerPlan 立即触发一次。POST /api/plans/:id/trigger
func (h *GovernanceHandler) TriggerPlan(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法计划 ID")
		return
	}
	run, created, err := h.cycles.TriggerPlan(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "计划不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	msg := "已创建批次"
	if !created {
		msg = "本分钟已有批次，未重复创建"
	}
	utils.SuccessWithMessage(c, msg, run)
}

// ListRuns 列出批次。GET /api/runs?project_id=&limit=
func (h *GovernanceHandler) ListRuns(c *gin.Context) {
	_, runs, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	list, err := runs.ListRuns(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, list)
}

// GetRun 批次详情，带执行单元计数。GET /api/runs/:id
func (h *GovernanceHandler) GetRun(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法批次 ID")
		return
	}
	_, runs, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	run, err := runs.GetRun(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "批次不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	stats, err := runs.TargetStats(c.Request.Context(), id)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"run": run, "target_stats": stats})
}

// ListTargets 批次下的执行单元。GET /api/runs/:id/targets?state=&limit=
func (h *GovernanceHandler) ListTargets(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法批次 ID")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	_, runs, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	list, err := runs.ListTargets(c.Request.Context(), id, c.Query("state"), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, list)
}

// Tick 手动推进一轮（后台每 60 秒也会跑一次，这里用于验收与排障）。
// POST /api/governance/tick
func (h *GovernanceHandler) Tick(c *gin.Context) {
	res, err := h.cycles.Tick(c.Request.Context(), 20)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "推进完成", res)
}

// ProbeAsset 对一个站点做真实可达性探测（会发 HTTP 请求）。POST /api/assets/:id/probe
func (h *GovernanceHandler) ProbeAsset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	report, err := h.verify.ProbeSite(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "资产不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "探测完成："+report.Verdict, report)
}

// ExecuteRun 立即跑一批执行单元（后台每 5 秒也会跑）。POST /api/runs/:id/execute
func (h *GovernanceHandler) ExecuteRun(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法批次 ID")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	stats, err := h.probes.ProcessOnce(c.Request.Context(), id, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "执行完成", stats)
}

// ArchiveLost 归档失联站点：先服务端复核，可达的不归档，归档的落审计。
// POST /api/governance/archive?days=30&limit=100&dry_run=1
func (h *GovernanceHandler) ArchiveLost(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	dryRun := c.Query("dry_run") == "1" || c.Query("dry_run") == "true"

	actor, _ := c.Get("username")
	name, _ := actor.(string)
	report, err := h.cleanup.ArchiveLost(c.Request.Context(), days, limit, dryRun, name, c.ClientIP())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	msg := "归档完成"
	if dryRun {
		msg = "预演完成，未改动数据"
	}
	utils.SuccessWithMessage(c, msg, report)
}

// ProtectAsset 给站点设人工删除保护期（期间不会被自动归档）。POST /api/assets/:id/protect
func (h *GovernanceHandler) ProtectAsset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	var body struct {
		Days int `json:"days"`
	}
	_ = c.ShouldBindJSON(&body)
	if err := h.cleanup.ProtectSite(c.Request.Context(), id, body.Days); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "资产不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已设置保护期", gin.H{"id": id, "days": body.Days})
}

// --- 指纹规则（条件树） ---

// SyncFingerprints 把内置规则集（dddd 快照 + 种子）幂等写入 PG。
// POST /api/governance/fingerprints/sync
func (h *GovernanceHandler) SyncFingerprints(c *gin.Context) {
	stats, err := h.fpSync.SyncEmbedded(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "指纹规则已同步", gin.H{"sources": stats})
}

// FingerprintSources 各来源最近一次同步状态。
// GET /api/governance/fingerprints/sources
func (h *GovernanceHandler) FingerprintSources(c *gin.Context) {
	r := repo.Default()
	if r == nil {
		utils.Error(c, utils.ErrCodeDatabaseError, "数据层未初始化")
		return
	}
	meta, err := r.FingerprintSync().ListSources(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	counts, err := r.FingerprintSync().CountBySource(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"sources": meta, "counts": counts})
}

// --- 关系图谱（G5） ---

// RebuildRelations 重建关系边与证据。POST /api/governance/relations/rebuild?project_id=
func (h *GovernanceHandler) RebuildRelations(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	stats, err := h.relations.Rebuild(c.Request.Context(), projectID)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "关系图谱已重建", gin.H{"by_type": stats})
}

// ListRelations 图谱查询。GET /api/relations?project_id=&type=&limit=
func (h *GovernanceHandler) ListRelations(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "500"))
	graph, err := h.relations.Graph(c.Request.Context(), projectID, c.Query("type"), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, graph)
}

// RelationIndexStatus 索引状态。GET /api/relations/index-status?project_id=
func (h *GovernanceHandler) RelationIndexStatus(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	status, err := h.relations.Status(c.Request.Context(), projectID)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, status)
}

// ReplayResults 把历史 scan_results 回放成 raw_records/sites。
// POST /api/governance/replay-results?project_id=&limit=
func (h *GovernanceHandler) ReplayResults(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "5000"))
	stats, err := h.replay.Replay(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "历史结果回放完成", stats)
}

func (h *GovernanceHandler) fpRepo() (repo.FingerprintRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().Fingerprints(), nil
}

// ListFingerprints 规则列表。GET /api/governance/fingerprints
func (h *GovernanceHandler) ListFingerprints(c *gin.Context) {
	fp, err := h.fpRepo()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	q := c.Query("q")
	if q == "" {
		q = c.Query("keyword")
	}
	category, source := c.Query("category"), c.Query("source")
	var enabled *bool
	switch c.Query("enabled") {
	case "1", "true":
		v := true
		enabled = &v
	case "0", "false":
		v := false
		enabled = &v
	}
	// 带分页/筛选参数走指纹库视图（覆盖 expression 规则）；否则保持旧的治理列表。
	if c.Query("page") != "" || q != "" || category != "" || source != "" || enabled != nil {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		rules, total, err := fp.ListRulesPage(c.Request.Context(), repo.FpRuleFilter{
			Keyword: q, Category: category, Source: source, Enabled: enabled,
			Page: page, PageSize: pageSize,
		})
		if err != nil {
			utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
			return
		}
		utils.SuccessWithPagination(c, rules, total, page, pageSize)
		return
	}
	rules, err := fp.ListRules(c.Request.Context(), false)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": rules, "total": len(rules)})
}

// UpsertFingerprint 新建或覆盖一条规则（按 name 唯一）。
// POST /api/governance/fingerprints
func (h *GovernanceHandler) UpsertFingerprint(c *gin.Context) {
	var body struct {
		Name       string          `json:"name" binding:"required"`
		Category   string          `json:"category"`
		Version    string          `json:"version"`
		Enabled    *bool           `json:"enabled"`
		Condition  *repo.Condition `json:"condition_tree"`
		Expression string          `json:"expression"`
		Source     string          `json:"source"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if body.Condition == nil && body.Expression == "" {
		utils.BadRequest(c, "condition_tree 与 expression 至少填一个")
		return
	}
	if body.Condition != nil {
		if err := service.ValidateCondition(body.Condition); err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
	}
	if body.Expression != "" {
		if _, err := reconkitfp.ParseExpression(body.Expression); err != nil {
			utils.BadRequest(c, "表达式解析失败: "+err.Error())
			return
		}
	}
	fp, err := h.fpRepo()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	dslVersion := 2
	if body.Condition == nil {
		dslVersion = 1
	}
	rule := &repo.FpRule{
		Name: body.Name, Category: body.Category, Version: body.Version,
		Enabled: enabled, DSLVersion: dslVersion, Condition: body.Condition,
		Expression: body.Expression, Source: body.Source,
	}
	if err := fp.UpsertRule(c.Request.Context(), rule); err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	h.fp.Invalidate() // 规则变了，缓存立刻失效
	utils.SuccessWithMessage(c, "已保存", rule)
}

// DeleteFingerprint 按名字删规则。DELETE /api/governance/fingerprints/:name
func (h *GovernanceHandler) DeleteFingerprint(c *gin.Context) {
	name := c.Param("name")
	fp, err := h.fpRepo()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if err := fp.DeleteRule(c.Request.Context(), name); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "规则不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	h.fp.Invalidate()
	utils.SuccessWithMessage(c, "已删除", nil)
}

// ToggleFingerprint 启停一条规则。POST /api/governance/fingerprints/:name/toggle
func (h *GovernanceHandler) ToggleFingerprint(c *gin.Context) {
	name := c.Param("name")
	var body struct {
		Enabled *bool `json:"enabled" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enabled == nil {
		utils.BadRequest(c, "enabled 必填")
		return
	}
	fp, err := h.fpRepo()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if err := fp.SetRuleEnabled(c.Request.Context(), name, *body.Enabled); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "规则不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	h.fp.Invalidate()
	utils.SuccessWithMessage(c, "已更新", gin.H{"name": name, "enabled": *body.Enabled})
}

// PreviewFingerprint 用样例响应试跑规则，不落库。
// POST /api/governance/fingerprints/preview
func (h *GovernanceHandler) PreviewFingerprint(c *gin.Context) {
	var body struct {
		Condition *repo.Condition `json:"condition_tree"`
		Sample    struct {
			StatusCode int               `json:"status_code"`
			Title      string            `json:"title"`
			Server     string            `json:"server"`
			Headers    map[string]string `json:"headers"`
			Body       string            `json:"body"`
		} `json:"sample"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if err := service.ValidateCondition(body.Condition); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	matched := h.fp.EvalTree(body.Condition, service.ResponseSnapshot{
		StatusCode: body.Sample.StatusCode,
		Title:      body.Sample.Title,
		Server:     body.Sample.Server,
		Headers:    body.Sample.Headers,
		Body:       body.Sample.Body,
	})
	utils.Success(c, gin.H{"matched": matched})
}

// SiteFingerprints 某站点命中的指纹。GET /api/assets/:id/fingerprints
func (h *GovernanceHandler) SiteFingerprints(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	fp, err := h.fpRepo()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	hits, err := fp.ListHits(c.Request.Context(), id)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": hits, "total": len(hits)})
}

// EngineUsageStatus 引擎查询额度面板（今日用量 + 近 7 天 + 限额）。
// @Router /api/governance/engine-usage [get]
func (h *GovernanceHandler) EngineUsageStatus(c *gin.Context) {
	utils.Success(c, service.GetEngineBudgetService().Status(c.Request.Context()))
}

// EngineUsageSetLimits 更新每引擎日限额（<=0 表示不限）。
// @Router /api/governance/engine-usage/limits [put]
func (h *GovernanceHandler) EngineUsageSetLimits(c *gin.Context) {
	var limits map[string]int
	if err := c.ShouldBindJSON(&limits); err != nil {
		utils.BadRequest(c, "请求体不是合法 JSON")
		return
	}
	budget := service.GetEngineBudgetService()
	if !budget.CanAccount() {
		utils.InternalError(c, "需要控制面（worker 无数据库）")
		return
	}
	if err := budget.SetLimits(c.Request.Context(), limits); err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "限额已保存", budget.Status(c.Request.Context()))
}
