package api

import (
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/internal/githubleak"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// GitHubMonitorHandler 项目 GitHub 泄露监控（迁移自 4zreco/internal/githubleak）。
// 规则按项目绑定，规则名落库即带项目名前缀，findings 溯源到项目。
type GitHubMonitorHandler struct{}

func NewGitHubMonitorHandler() *GitHubMonitorHandler { return &GitHubMonitorHandler{} }

func (h *GitHubMonitorHandler) projectID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return 0, false
	}
	return id, true
}

// Overview 设置 + 规则 + 统计 + 运行态。
func (h *GitHubMonitorHandler) Overview(c *gin.Context) {
	projectID, ok := h.projectID(c)
	if !ok {
		return
	}
	r := repo.Default().GitHubMonitor()
	settings, err := r.GetSettings(c.Request.Context(), projectID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	rules, err := r.ListRules(c.Request.Context(), projectID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}

	var stats githubleak.Stats
	var latest githubleak.RunRecord
	_, merr := service.GetGitHubMonitor()
	if merr == nil {
		if store := service.GitHubMonitorStore(); store != nil {
			stats, _ = store.Stats(c.Request.Context(), nil)
			latest, _ = store.LatestRun(c.Request.Context())
		}
	}

	utils.Success(c, gin.H{
		"settings":      settings,
		"rules":         rules,
		"stats":         stats,
		"latest_run":    latest,
		"monitor_ready": merr == nil,
		"monitor_error": errString(merr),
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// SaveSettings 启用开关 / token / 间隔。
func (h *GitHubMonitorHandler) SaveSettings(c *gin.Context) {
	projectID, ok := h.projectID(c)
	if !ok {
		return
	}
	var req struct {
		Enabled         bool   `json:"enabled"`
		Token           string `json:"token"`
		IntervalSeconds int    `json:"interval_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法")
		return
	}
	if req.Enabled && strings.TrimSpace(req.Token) == "" {
		// 已配过 token 才允许只开开关
		old, err := repo.Default().GitHubMonitor().GetSettings(c.Request.Context(), projectID)
		if err != nil || (old != nil && !old.TokenConfigured) {
			utils.BadRequest(c, "请先配置 GitHub Token（settings → tokens(classic) 需 repo 与 code search 权限）")
			return
		}
	}
	r := repo.Default().GitHubMonitor()
	name, err := r.ProjectName(c.Request.Context(), projectID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	if err := r.UpsertSettings(c.Request.Context(), &repo.GitHubMonitorSettings{
		ProjectID:       projectID,
		Enabled:         req.Enabled,
		Token:           req.Token,
		IntervalSeconds: req.IntervalSeconds,
	}); err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	// 首次启用且没有任何规则：从项目名自动生成一条关键词规则
	rules, _ := r.ListRules(c.Request.Context(), projectID)
	if req.Enabled && len(rules) == 0 && strings.TrimSpace(name) != "" {
		if _, err := r.CreateRule(c.Request.Context(), &repo.GitHubMonitorRule{
			ProjectID: projectID,
			Name:      name,
			Keywords:  []string{name},
			Enabled:   true,
		}); err != nil {
			utils.InternalError(c, "自动建规则失败: "+err.Error())
			return
		}
	}
	utils.SuccessWithMessage(c, "已保存，监控循环 2 分钟内生效", gin.H{"saved": true})
}

// ListRules 规则列表。
func (h *GitHubMonitorHandler) ListRules(c *gin.Context) {
	projectID, ok := h.projectID(c)
	if !ok {
		return
	}
	rules, err := repo.Default().GitHubMonitor().ListRules(c.Request.Context(), projectID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, rules)
}

// CreateRule 新增规则；规则名缺省用项目名。
func (h *GitHubMonitorHandler) CreateRule(c *gin.Context) {
	projectID, ok := h.projectID(c)
	if !ok {
		return
	}
	var req struct {
		Name     string   `json:"name"`
		Keywords []string `json:"keywords"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法")
		return
	}
	cleaned := make([]string, 0, len(req.Keywords))
	for _, k := range req.Keywords {
		if k = strings.TrimSpace(k); k != "" {
			cleaned = append(cleaned, k)
		}
	}
	if len(cleaned) == 0 {
		utils.BadRequest(c, "至少一个关键词")
		return
	}
	r := repo.Default().GitHubMonitor()
	if strings.TrimSpace(req.Name) == "" {
		name, nerr := r.ProjectName(c.Request.Context(), projectID)
		if nerr != nil {
			utils.InternalError(c, nerr.Error())
			return
		}
		req.Name = name
	}
	rule, err := r.CreateRule(c.Request.Context(), &repo.GitHubMonitorRule{
		ProjectID: projectID,
		Name:      req.Name,
		Keywords:  cleaned,
		Enabled:   true,
	})
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "规则已添加，监控循环 2 分钟内生效", rule)
}

// DeleteRule 删除规则。
func (h *GitHubMonitorHandler) DeleteRule(c *gin.Context) {
	projectID, ok := h.projectID(c)
	if !ok {
		return
	}
	ruleID, err := strconv.ParseInt(c.Param("rid"), 10, 64)
	if err != nil || ruleID <= 0 {
		utils.BadRequest(c, "规则 ID 不合法")
		return
	}
	if err := repo.Default().GitHubMonitor().DeleteRule(c.Request.Context(), projectID, ruleID); err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "规则已删除", nil)
}

// ListFindings 本项目的命中列表（按规则名圈定）。
func (h *GitHubMonitorHandler) ListFindings(c *gin.Context) {
	projectID, ok := h.projectID(c)
	if !ok {
		return
	}
	r := repo.Default().GitHubMonitor()
	rules, err := r.ListRules(c.Request.Context(), projectID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	projectName, err := r.ProjectName(c.Request.Context(), projectID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, projectName+": "+rule.Name)
	}
	store := service.GitHubMonitorStore()
	if store == nil {
		utils.InternalError(c, "监控服务未就绪")
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	filter := githubleak.ListFilter{
		Status:    c.Query("status"),
		Keyword:   c.Query("keyword"),
		Query:     c.Query("q"),
		Page:      page,
		PageSize:  pageSize,
		RuleNames: names,
	}
	result, err := store.List(c.Request.Context(), filter)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, result)
}

// UpdateFindingStatus 处置命中（确认/忽略/已处置）。
func (h *GitHubMonitorHandler) UpdateFindingStatus(c *gin.Context) {
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法")
		return
	}
	store := service.GitHubMonitorStore()
	if store == nil {
		utils.InternalError(c, "监控服务未就绪")
		return
	}
	finding, err := store.UpdateStatus(c.Request.Context(), c.Param("fid"), req.Status)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已更新", finding)
}
