package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// GovernanceHandler 是资产治理域「周期」部分的 HTTP 入口：
// 种子 → 计划 → 批次 → 执行单元。
type GovernanceHandler struct {
	cycles  *service.CycleService
	probes  *service.ProbeExecutor
	verify  *service.VerifyService
	cleanup *service.CleanupService
}

func NewGovernanceHandler() *GovernanceHandler {
	return &GovernanceHandler{
		cycles:  service.NewCycleService(),
		probes:  service.NewProbeExecutor(8),
		verify:  service.NewVerifyService(),
		cleanup: service.NewCleanupService(),
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
	case "domain", "cidr", "company", "repo", "app", "dict":
	default:
		utils.BadRequest(c, "kind 只支持 domain / cidr / company / repo / app / dict")
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
		Enabled       *bool `json:"enabled"`
		IntervalHours *int  `json:"interval_hours"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	if body.IntervalHours != nil && (*body.IntervalHours < 1 || *body.IntervalHours > 720) {
		utils.BadRequest(c, "interval_hours 需在 1..720")
		return
	}

	seeds, _, err := h.stores()
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if err := seeds.UpdatePlan(c.Request.Context(), id, body.Enabled, body.IntervalHours); err != nil {
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
