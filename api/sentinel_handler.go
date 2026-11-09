package api

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
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

// ImportArchive 上传代码压缩包（multipart：file + 可选 name）导入为本地静态仓库，
// 解包 → 建 mirror → 采集落库 → 自动入队判定。与 MCP sentinel_import_archive
// 共用 service.ImportArchive；REST 侧放宽到 32MB。
func (h *SentinelHandler) ImportArchive(c *gin.Context) {
	const maxUpload = 32 << 20
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	file, err := c.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "缺少 file 字段（multipart/form-data）: "+err.Error())
		return
	}
	fh, err := file.Open()
	if err != nil {
		utils.BadRequest(c, "读取上传文件失败: "+err.Error())
		return
	}
	defer fh.Close()
	content, err := io.ReadAll(fh)
	if err != nil {
		utils.BadRequest(c, "读取上传文件失败: "+err.Error())
		return
	}
	cfg := config.Loaded()
	if cfg == nil {
		utils.InternalError(c, "配置未加载")
		return
	}
	src := service.NewSentinelSource(cfg.Sentinel)
	res, err := src.ImportArchive(c.Request.Context(), c.PostForm("name"), file.Filename, content)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	h.audit(c, "repo.import_archive", res.RepoID, map[string]interface{}{
		"full_name": res.FullName, "inserted": res.Inserted, "synthesized": res.Synthesized,
	})
	utils.Success(c, res)
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
		VulnClasses:     parseVulnClasses(c.Query("vuln_class")),
		MinSeverity:     strings.TrimSpace(c.Query("min_severity")),
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

	// 判定查询必须区分「没判过」和「查询本身失败」：吞掉错误会把两者混成同一个
	// 「尚未判定」UI 状态（典型事故：judgment 表缺新列没跑迁移，列表正常详情报错）。
	var judgment *repo.CommitJudgment
	j, jErr := h.store.GetJudgment(c.Request.Context(), id)
	switch {
	case jErr == nil:
		judgment = j
	case errors.Is(jErr, repo.ErrNotFound):
		// 尚未判定：正常路径
	default:
		log.Printf("[Sentinel] 查询判定详情失败 commit_id=%d: %v", id, jErr)
		utils.InternalError(c, "查询判定详情失败（多为数据库迁移未执行，请先跑 docs/sql/apply_all.sh）: "+jErr.Error())
		return
	}
	findings, fErr := h.store.ListFindingsByCommit(c.Request.Context(), id)
	if fErr != nil {
		log.Printf("[Sentinel] 查询提交发现失败 commit_id=%d: %v", id, fErr)
	}
	if findings == nil {
		findings = []*repo.CommitFinding{}
	}

	utils.Success(c, gin.H{
		"commit":   commit,
		"judgment": judgment,
		"findings": findings,
	})
}

// JudgeCommit 手动触发判定排队。「永不重判」按模型维度在 Judge() 内判断：
// 外部 agent 经 MCP 提交的判定（model=agent:*）不算内部已判，不挡内部重判排队。
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
		Status:      strings.TrimSpace(c.Query("status")),
		Severity:    strings.TrimSpace(c.Query("severity")),
		VulnClasses: parseVulnClasses(c.Query("vuln_class")),
		MinSeverity: strings.TrimSpace(c.Query("min_severity")),
		RepoID:      strings.TrimSpace(c.Query("repo_id")),
		Page:        page,
		Size:        size,
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

// parseVulnClasses 解析逗号分隔的 vuln_class 筛选参数（如 vuln_class=SQLI,RCE）。
func parseVulnClasses(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ExportFindings 导出发现报告（md / pdf）。
// 复用列表筛选参数；PDF 依赖本机 chrome/chromium，缺失时报错提示改用 md。
func (h *SentinelHandler) ExportFindings(c *gin.Context) {
	filter := repo.FindingFilter{
		Status:      strings.TrimSpace(c.Query("status")),
		Severity:    strings.TrimSpace(c.Query("severity")),
		VulnClasses: parseVulnClasses(c.Query("vuln_class")),
		MinSeverity: strings.TrimSpace(c.Query("min_severity")),
		RepoID:      strings.TrimSpace(c.Query("repo_id")),
	}
	name, mime, body, err := service.ExportSentinelFindings(c.Request.Context(), filter, c.Query("format"))
	if err != nil {
		utils.InternalError(c, "导出失败: "+err.Error())
		return
	}
	h.audit(c, "finding.export", name, map[string]interface{}{"format": c.Query("format"), "bytes": len(body)})
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	c.Data(200, mime, body)
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

// PatchFinding 流转发现状态（open/confirmed/ignored/resolved）；
// 确认时 service 层自动固化 patch 证据产物。
func (h *SentinelHandler) PatchFinding(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "发现 id 非法")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	f, err := service.SetFindingStatus(c.Request.Context(), id, strings.TrimSpace(body.Status))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "发现不存在")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	h.audit(c, "finding.status", strconv.FormatInt(id, 10), map[string]interface{}{"status": f.Status})
	utils.SuccessWithMessage(c, "发现状态已更新", f)
}

// ListFindingArtifacts 某发现下的产物列表（含 content，供前端预览）。
func (h *SentinelHandler) ListFindingArtifacts(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "发现 id 非法")
		return
	}
	items, err := h.store.ListArtifacts(c.Request.Context(), id)
	if err != nil {
		utils.InternalError(c, "查询产物失败: "+err.Error())
		return
	}
	if items == nil {
		items = []*repo.CommitArtifact{}
	}
	utils.Success(c, items)
}

// CreateFindingArtifact 人工新增产物（粘贴 PoC/模板/报告），落 draft 待审。
func (h *SentinelHandler) CreateFindingArtifact(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "发现 id 非法")
		return
	}
	var body struct {
		Kind    string `json:"kind"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	a, err := service.AddFindingArtifact(c.Request.Context(), id, body.Kind, body.Title, body.Content)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "发现不存在")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	h.audit(c, "artifact.create", strconv.FormatInt(a.ID, 10), map[string]interface{}{"kind": a.Kind, "finding_id": id})
	utils.SuccessWithMessage(c, "产物已创建（draft，待审核）", a)
}

// GenerateFindingNuclei 让模型依据修复 diff 草拟 nuclei 模板（同步，落 draft）。
func (h *SentinelHandler) GenerateFindingNuclei(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "发现 id 非法")
		return
	}
	a, err := service.GenerateNucleiTemplate(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "发现不存在")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	h.audit(c, "artifact.generate_nuclei", strconv.FormatInt(a.ID, 10), map[string]interface{}{"finding_id": id, "title": a.Title})
	utils.SuccessWithMessage(c, "nuclei 模板已生成（draft，请人工审核后再 verified/发布）", a)
}

// SetArtifactStatus 流转产物状态（draft/pending_review/verified/rejected/deprecated）。
func (h *SentinelHandler) SetArtifactStatus(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "产物 id 非法")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	a, err := service.SetArtifactStatus(c.Request.Context(), id, strings.TrimSpace(body.Status))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "产物不存在")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	h.audit(c, "artifact.status", strconv.FormatInt(id, 10), map[string]interface{}{"status": a.Status})
	utils.SuccessWithMessage(c, "产物状态已更新", a)
}

// DownloadArtifact 下载产物内容；非 verified 一律 403（铁律：未审核产物不可下发）。
func (h *SentinelHandler) DownloadArtifact(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "产物 id 非法")
		return
	}
	a, err := service.GetArtifactForDownload(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "产物不存在")
			return
		}
		if errors.Is(err, service.ErrArtifactNotVerified) {
			utils.Error(c, utils.ErrCodeForbidden, err.Error())
			return
		}
		utils.InternalError(c, "读取产物失败: "+err.Error())
		return
	}
	filename := a.Title
	if filename == "" {
		filename = fmt.Sprintf("artifact-%d", a.ID)
	}
	filename = strings.Map(func(r rune) rune {
		if r > 32 && r < 127 && r != '/' && r != '\\' {
			return r
		}
		return -1
	}, filename)
	if filename == "" {
		filename = fmt.Sprintf("artifact-%d", a.ID)
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename+".txt"))
	c.Data(200, "text/plain; charset=utf-8", []byte(a.Content))
}

// PublishArtifact 把 verified 的 nuclei 模板发布到 PoC 库（pocs 表），返回模板 id。
func (h *SentinelHandler) PublishArtifact(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "产物 id 非法")
		return
	}
	templateID, err := service.PublishArtifact(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "产物不存在")
			return
		}
		if errors.Is(err, service.ErrArtifactNotVerified) {
			utils.Error(c, utils.ErrCodeForbidden, err.Error())
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	h.audit(c, "artifact.publish", strconv.FormatInt(id, 10), map[string]interface{}{"template_id": templateID})
	utils.SuccessWithMessage(c, "已发布到 PoC 库", gin.H{"template_id": templateID})
}

// ReproFinding 把发现送进 pocsmith 差分复现队列（worker 在独立进程）。
func (h *SentinelHandler) ReproFinding(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "发现 id 非法")
		return
	}
	if _, err := h.store.GetFinding(c.Request.Context(), id); err != nil {
		utils.NotFound(c, "发现不存在")
		return
	}
	q := service.DefaultSentinelQueue()
	if q == nil {
		utils.BadRequest(c, "提交哨兵未启用（sentinel.enabled=false）")
		return
	}
	if err := q.EnqueueRepro(c.Request.Context(), id); err != nil {
		utils.InternalError(c, "复现入队失败: "+err.Error())
		return
	}
	h.audit(c, "finding.repro", strconv.FormatInt(id, 10), nil)
	utils.SuccessWithMessage(c, "已加入复现队列（由 pocsmith 进程执行）", gin.H{"finding_id": id})
}
