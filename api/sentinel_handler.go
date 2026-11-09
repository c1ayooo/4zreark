package api

import (
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// SentinelHandler 提交哨兵（CommitSentinel）HTTP 入口。
// 只做参数解析与响应封装，业务规则全在 service/repo 层。
type SentinelHandler struct {
	store *repo.Sentinel
	cfg   service.SentinelConfigView
}

// NewSentinelHandler 构造处理器。
func NewSentinelHandler() *SentinelHandler {
	return &SentinelHandler{
		store: repo.Default().Sentinel(),
		cfg:   service.SentinelConfig(),
	}
}

// Overview 总览统计。
func (h *SentinelHandler) Overview(c *gin.Context) {
	ov, err := h.store.Overview(c.Request.Context(), []string{
		service.SentinelCollectQueueName, service.SentinelJudgeQueueName,
	})
	if err != nil {
		utils.InternalError(c, "统计失败: "+err.Error())
		return
	}
	utils.Success(c, ov)
}

// ListRepos 仓库列表。
func (h *SentinelHandler) ListRepos(c *gin.Context) {
	items, err := h.store.ListRepos(c.Request.Context(), strings.TrimSpace(c.Query("keyword")))
	if err != nil {
		utils.InternalError(c, "查询仓库失败: "+err.Error())
		return
	}
	if items == nil {
		items = []*repo.GitRepo{}
	}
	utils.Success(c, gin.H{"items": items, "clone_hosts": h.cfg.CloneHosts})
}

type sentinelRepoCreateReq struct {
	FullName        string `json:"full_name"`
	CloneURL        string `json:"clone_url"`
	Branch          string `json:"branch"`
	IntervalMinutes int    `json:"interval_minutes"`
	Enabled         *bool  `json:"enabled"`
}

// CreateRepo 新增仓库。
func (h *SentinelHandler) CreateRepo(c *gin.Context) {
	var req sentinelRepoCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	cloneURL, err := service.ValidateCloneURL(req.CloneURL, h.cfg.CloneHosts)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	fullName := strings.TrimSpace(req.FullName)
	if fullName == "" {
		fullName = deriveFullName(cloneURL)
	}
	if strings.Count(fullName, "/") != 1 {
		utils.BadRequest(c, "full_name 需要是 owner/repo 形式")
		return
	}

	interval := req.IntervalMinutes
	if interval < 10 {
		interval = 60
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	item := &repo.GitRepo{
		ID:              oid.NewObjectID().Hex(),
		FullName:        fullName,
		CloneURL:        cloneURL,
		DefaultBranch:   "main",
		Branch:          strings.TrimSpace(req.Branch),
		IntervalMinutes: interval,
		Enabled:         enabled,
	}
	if err := h.store.CreateRepo(c.Request.Context(), item); err != nil {
		if err == repo.ErrDuplicate {
			utils.BadRequest(c, "该仓库已存在")
			return
		}
		utils.InternalError(c, "新增仓库失败: "+err.Error())
		return
	}
	h.audit(c, "repo.create", item.ID, map[string]interface{}{"full_name": item.FullName})

	// 新建后立刻排一次采集，用户不必等下一个调度周期。
	if q := service.DefaultSentinelQueue(); q != nil {
		if err := q.EnqueueCollect(c.Request.Context(), item.ID); err != nil {
			utils.SuccessWithMessage(c, "仓库已创建，但采集入队失败: "+err.Error(), item)
			return
		}
	}
	utils.SuccessWithMessage(c, "已创建并开始采集", item)
}

type sentinelRepoUpdateReq struct {
	CloneURL        *string `json:"clone_url"`
	Branch          *string `json:"branch"`
	DefaultBranch   *string `json:"default_branch"`
	IntervalMinutes *int    `json:"interval_minutes"`
	Enabled         *bool   `json:"enabled"`
}

// UpdateRepo 编辑仓库。
func (h *SentinelHandler) UpdateRepo(c *gin.Context) {
	id := c.Param("id")
	var req sentinelRepoUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	fields := map[string]interface{}{}
	if req.CloneURL != nil {
		cloneURL, err := service.ValidateCloneURL(*req.CloneURL, h.cfg.CloneHosts)
		if err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
		fields["clone_url"] = cloneURL
	}
	if req.Branch != nil {
		fields["branch"] = strings.TrimSpace(*req.Branch)
	}
	if req.DefaultBranch != nil {
		fields["default_branch"] = strings.TrimSpace(*req.DefaultBranch)
	}
	if req.IntervalMinutes != nil {
		interval := *req.IntervalMinutes
		if interval < 10 {
			utils.BadRequest(c, "采集间隔不能小于 10 分钟")
			return
		}
		fields["interval_minutes"] = interval
	}
	if req.Enabled != nil {
		fields["enabled"] = *req.Enabled
	}
	if err := h.store.UpdateRepo(c.Request.Context(), id, fields); err != nil {
		if err == repo.ErrNotFound {
			utils.NotFound(c, "仓库不存在")
			return
		}
		utils.BadRequest(c, "更新失败: "+err.Error())
		return
	}
	h.audit(c, "repo.update", id, fields)
	utils.SuccessWithMessage(c, "已更新", nil)
}

// DeleteRepo 删除仓库。
func (h *SentinelHandler) DeleteRepo(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteRepo(c.Request.Context(), id); err != nil {
		if err == repo.ErrNotFound {
			utils.NotFound(c, "仓库不存在")
			return
		}
		utils.InternalError(c, "删除失败: "+err.Error())
		return
	}
	h.audit(c, "repo.delete", id, nil)
	utils.SuccessWithMessage(c, "已删除", nil)
}

// CollectRepo 立即触发一次采集。
func (h *SentinelHandler) CollectRepo(c *gin.Context) {
	id := c.Param("id")
	if _, err := h.store.GetRepo(c.Request.Context(), id); err != nil {
		utils.NotFound(c, "仓库不存在")
		return
	}
	q := service.DefaultSentinelQueue()
	if q == nil {
		utils.BadRequest(c, "提交哨兵未启用（sentinel.enabled=false）")
		return
	}
	if err := q.EnqueueCollect(c.Request.Context(), id); err != nil {
		utils.InternalError(c, "采集入队失败: "+err.Error())
		return
	}
	h.audit(c, "repo.collect", id, nil)
	utils.SuccessWithMessage(c, "已加入采集队列", nil)
}

// ListCommits 提交列表（服务端分页 + 筛选）。
func (h *SentinelHandler) ListCommits(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 200 {
		size = 20
	}

	status := strings.TrimSpace(c.Query("status"))
	if status == "" && c.Query("judged") == "false" {
		status = "pending"
	}
	filter := repo.CommitFilter{
		RepoID:          strings.TrimSpace(c.Query("repo_id")),
		SHA:             strings.TrimSpace(c.Query("sha")),
		Status:          status,
		OnlySecurityFix: c.Query("security_fix") == "true" || c.Query("judged") == "hit",
		Page:            page,
		Size:            size,
	}
	if since := parseSentinelTime(c.Query("since")); since != nil {
		filter.Since = since
	}
	if until := parseSentinelTime(c.Query("until")); until != nil {
		filter.Until = until
	}

	items, total, err := h.store.ListCommits(c.Request.Context(), filter)
	if err != nil {
		utils.InternalError(c, "查询提交失败: "+err.Error())
		return
	}
	if items == nil {
		items = []*repo.CommitListItem{}
	}
	utils.SuccessWithPagination(c, items, total, page, size)
}

// GetCommit 提交详情（含 diff、判定与发现）。
func (h *SentinelHandler) GetCommit(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "提交 id 非法")
		return
	}
	commit, err := h.store.GetCommit(c.Request.Context(), id)
	if err != nil {
		if err == repo.ErrNotFound {
			utils.NotFound(c, "提交不存在")
			return
		}
		utils.InternalError(c, "查询提交失败: "+err.Error())
		return
	}

	var judgment *repo.CommitJudgment
	if j, jErr := h.store.GetJudgment(c.Request.Context(), id); jErr == nil {
		judgment = j
	}
	findings, _ := h.store.ListFindingsByCommit(c.Request.Context(), id)
	if findings == nil {
		findings = []*repo.CommitFinding{}
	}

	utils.Success(c, gin.H{
		"commit":   commit,
		"judgment": judgment,
		"findings": findings,
	})
}

// JudgeCommit 手动触发判定排队（已判定过的提交永不重判）。
func (h *SentinelHandler) JudgeCommit(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "提交 id 非法")
		return
	}
	if _, err := h.store.GetCommit(c.Request.Context(), id); err != nil {
		utils.NotFound(c, "提交不存在")
		return
	}
	if existing, err := h.store.GetJudgment(c.Request.Context(), id); err == nil && existing != nil {
		utils.SuccessWithMessage(c, "该提交已判定，按规则永不重判", existing)
		return
	}
	q := service.DefaultSentinelQueue()
	if q == nil {
		utils.BadRequest(c, "提交哨兵未启用（sentinel.enabled=false）")
		return
	}
	if err := q.EnqueueJudge(c.Request.Context(), id); err != nil {
		utils.InternalError(c, "判定入队失败: "+err.Error())
		return
	}
	h.audit(c, "commit.judge", strconv.FormatInt(id, 10), nil)
	utils.SuccessWithMessage(c, "已加入判定队列", nil)
}

// ListRuns 采集/判定批次列表。
func (h *SentinelHandler) ListRuns(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	items, err := h.store.ListRuns(c.Request.Context(), c.Query("run_type"), limit)
	if err != nil {
		utils.InternalError(c, "查询批次失败: "+err.Error())
		return
	}
	if items == nil {
		items = []*repo.SentinelRun{}
	}
	utils.Success(c, items)
}

// ListRunEvents 批次事件（断线重连后按 seq 补齐）。
func (h *SentinelHandler) ListRunEvents(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "批次 id 非法")
		return
	}
	after, _ := strconv.ParseInt(c.DefaultQuery("after_seq", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := h.store.EventsAfter(c.Request.Context(), id, after, limit)
	if err != nil {
		utils.InternalError(c, "查询事件失败: "+err.Error())
		return
	}
	if events == nil {
		events = []*repo.SentinelRunEvent{}
	}
	utils.Success(c, events)
}

// ListFindings 发现列表（产物）：分页 + 状态/严重度/仓库筛选。
func (h *SentinelHandler) ListFindings(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 200 {
		size = 20
	}
	items, total, err := h.store.ListFindings(c.Request.Context(), repo.FindingFilter{
		Status:   strings.TrimSpace(c.Query("status")),
		Severity: strings.TrimSpace(c.Query("severity")),
		RepoID:   strings.TrimSpace(c.Query("repo_id")),
		Page:     page,
		Size:     size,
	})
	if err != nil {
		utils.InternalError(c, "查询发现失败: "+err.Error())
		return
	}
	if items == nil {
		items = []*repo.FindingListItem{}
	}
	utils.SuccessWithPagination(c, items, total, page, size)
}

// audit 记录一次写操作；失败只打日志，不影响主流程。
func (h *SentinelHandler) audit(c *gin.Context, action, target string, detail map[string]interface{}) {
	actor := c.GetString("username")
	if actor == "" {
		actor = "system"
	}
	if err := h.store.InsertAudit(c.Request.Context(), actor, action, target, detail); err != nil {
		log.Printf("[Sentinel] 审计写入失败 action=%s target=%s: %v", action, target, err)
	}
}

// deriveFullName 从 clone url 推导 owner/repo。
func deriveFullName(cloneURL string) string {
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

// parseSentinelTime 接受 RFC3339 或 YYYY-MM-DD。
func parseSentinelTime(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return &t
		}
	}
	return nil
}
