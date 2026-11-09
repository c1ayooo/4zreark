package api

import (
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/internal/githubleak"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// GitHubLeakAdminHandler 泄露监控全局运维端点（迁移自 4zreco 的 17 端点中全局资源部分：
// 手动巡查/明文补全/误报抑制/水线/规则精度/自动建规则/历史清理/运行态与统计）。
// 包层方法（githubleak.Service/Store）签名与旧项目一致，本 handler 只做协议转换。
type GitHubLeakAdminHandler struct{}

func NewGitHubLeakAdminHandler() *GitHubLeakAdminHandler { return &GitHubLeakAdminHandler{} }

// leak 取监控内核；未就绪直接回 503。
func (h *GitHubLeakAdminHandler) leak(c *gin.Context) *githubleak.Service {
	svc := service.GitHubLeakService()
	if svc == nil {
		utils.InternalError(c, "监控服务未就绪")
		return nil
	}
	return svc
}

// mapLeakError 把包层哨兵错误映射为合适的状态码：Busy→409、Unconfigured→400。
func mapLeakError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, githubleak.ErrBusy):
		utils.SuccessWithMessage(c, "监控已在运行中（上一轮未结束）", gin.H{"accepted": false, "busy": true})
	case errors.Is(err, githubleak.ErrUnconfigured):
		utils.BadRequest(c, "监控未配置（没有启用规则或可用 token）")
	default:
		utils.InternalError(c, err.Error())
	}
}

// RuntimeStatus 运行态（轮次/水线/配置摘要），前端运维卡片用。
func (h *GitHubLeakAdminHandler) RuntimeStatus(c *gin.Context) {
	svc := h.leak(c)
	if svc == nil {
		return
	}
	rt, err := svc.RuntimeStatus(c.Request.Context())
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, rt)
}

// Stats 命中统计（分状态计数）。
func (h *GitHubLeakAdminHandler) Stats(c *gin.Context) {
	store := service.GitHubMonitorStore()
	if store == nil {
		utils.InternalError(c, "监控服务未就绪")
		return
	}
	stats, err := store.Stats(c.Request.Context(), nil)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, stats)
}

// Run 手动触发一轮巡查。轮次已在跑时幂等返回 busy=true（不视为错误）。
func (h *GitHubLeakAdminHandler) Run(c *gin.Context) {
	svc := h.leak(c)
	if svc == nil {
		return
	}
	if err := svc.Trigger(c.Request.Context()); err != nil {
		mapLeakError(c, err)
		return
	}
	utils.SuccessWithMessage(c, "已加入巡查队列", gin.H{"accepted": true})
}

// Backfill 补全最近命中的明文密钥值（内部上限 50 条/次）。
func (h *GitHubLeakAdminHandler) Backfill(c *gin.Context) {
	svc := h.leak(c)
	if svc == nil {
		return
	}
	filled, err := svc.BackfillSecretValues(c.Request.Context(), 50)
	if err != nil {
		mapLeakError(c, err)
		return
	}
	utils.SuccessWithMessage(c, "补全完成", gin.H{"filled": filled})
}

// ListSuppressions 误报抑制规则列表。
func (h *GitHubLeakAdminHandler) ListSuppressions(c *gin.Context) {
	svc := h.leak(c)
	if svc == nil {
		return
	}
	items, err := svc.ListSuppressions(c.Request.Context())
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	if items == nil {
		items = []githubleak.Suppression{}
	}
	utils.Success(c, gin.H{"suppressions": items})
}

// AddSuppression 新增抑制规则（pattern_type: repo/org/path_glob/fingerprint_prefix/rule）。
func (h *GitHubLeakAdminHandler) AddSuppression(c *gin.Context) {
	var req struct {
		PatternType string `json:"pattern_type" binding:"required"`
		Pattern     string `json:"pattern" binding:"required"`
		Note        string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法（需要 pattern_type 与 pattern）")
		return
	}
	svc := h.leak(c)
	if svc == nil {
		return
	}
	created, err := svc.AddSuppression(c.Request.Context(), req.PatternType, req.Pattern, req.Note, sessionUser(c))
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已保存", gin.H{"created": created})
}

// DeleteSuppression 删除抑制规则。
func (h *GitHubLeakAdminHandler) DeleteSuppression(c *gin.Context) {
	svc := h.leak(c)
	if svc == nil {
		return
	}
	deleted, err := svc.DeleteSuppression(c.Request.Context(), c.Param("sid"))
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", gin.H{"deleted": deleted})
}

// ResetWaterline 重置指定规则（query 为空=全部规则）的搜索水线，下轮从头回扫。
func (h *GitHubLeakAdminHandler) ResetWaterline(c *gin.Context) {
	var req struct {
		Query string `json:"query"`
	}
	// 容忍空 body：curl -X POST 不带数据也应重置全部
	_ = c.ShouldBindJSON(&req)
	svc := h.leak(c)
	if svc == nil {
		return
	}
	n, err := svc.ResetWaterline(c.Request.Context(), strings.TrimSpace(req.Query))
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "水线已重置", gin.H{"reset": n})
}

// RulePrecisionStats 规则精度统计（确认/误报/忽略与精确率），指导关键词治理。
func (h *GitHubLeakAdminHandler) RulePrecisionStats(c *gin.Context) {
	svc := h.leak(c)
	if svc == nil {
		return
	}
	rules, err := svc.RulePrecisionStats(c.Request.Context())
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	if rules == nil {
		rules = []githubleak.RulePrecision{}
	}
	utils.Success(c, gin.H{"rules": rules})
}

// AddAutoRules 从域名/org 自动生成监控规则（平台资产反哺监控）。
func (h *GitHubLeakAdminHandler) AddAutoRules(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
		Org    string `json:"org"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法")
		return
	}
	if strings.TrimSpace(req.Domain) == "" && strings.TrimSpace(req.Org) == "" {
		utils.BadRequest(c, "domain 与 org 至少填一个")
		return
	}
	svc := h.leak(c)
	if svc == nil {
		return
	}
	rules, added, err := svc.AddAutoRules(strings.TrimSpace(req.Domain), strings.TrimSpace(req.Org))
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	if rules == nil {
		rules = []githubleak.Rule{}
	}
	utils.SuccessWithMessage(c, "已生成", gin.H{"added": added, "rules": rules})
}

// CleanupPreview 历史噪音清理预览（两段式第一步，只报不删）。
func (h *GitHubLeakAdminHandler) CleanupPreview(c *gin.Context) {
	h.cleanup(c, false)
}

// CleanupApply 历史噪音清理执行（两段式第二步，确认预览后调用）。
func (h *GitHubLeakAdminHandler) CleanupApply(c *gin.Context) {
	h.cleanup(c, true)
}

func (h *GitHubLeakAdminHandler) cleanup(c *gin.Context, apply bool) {
	svc := h.leak(c)
	if svc == nil {
		return
	}
	report, err := svc.CleanupNoiseFindings(c.Request.Context(), apply)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	msg := "预览完成（未删除，确认后调 apply）"
	if apply {
		msg = "清理完成"
	}
	utils.SuccessWithMessage(c, msg, report)
}

// ---- 全局命中（不带项目过滤，供独立「敏感信息监控」页使用）----

// GlobalFindings 全库命中列表。ListFilter.RuleNames 留空 = 不过滤项目前缀，
// 与项目级端点（按「项目名: 规则名」圈定）共用同一张 findings 表而不互相干扰。
func (h *GitHubLeakAdminHandler) GlobalFindings(c *gin.Context) {
	store := service.GitHubMonitorStore()
	if store == nil {
		utils.InternalError(c, "监控服务未就绪")
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	result, err := store.List(c.Request.Context(), githubleak.ListFilter{
		Status:   c.Query("status"),
		Keyword:  c.Query("keyword"),
		Query:    c.Query("q"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	if result.Items == nil {
		result.Items = []githubleak.Finding{}
	}
	utils.Success(c, result)
}

// GlobalUpdateFindingStatus 全局命中处置（确认/误报/忽略/已处置）。
// 与项目级处置共用 silenceFalsePositive 副作用，行为保持一致。
func (h *GitHubLeakAdminHandler) GlobalUpdateFindingStatus(c *gin.Context) {
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法（需要 status 字段）")
		return
	}
	svc := h.leak(c)
	store := service.GitHubMonitorStore()
	if svc == nil || store == nil {
		if svc == nil {
			return
		}
		utils.InternalError(c, "监控服务未就绪")
		return
	}
	finding, err := store.UpdateStatus(c.Request.Context(), c.Param("fid"), req.Status)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	if req.Status == githubleak.StatusFalsePositive {
		silenceFalsePositive(c, svc, finding)
	}
	utils.SuccessWithMessage(c, "已更新", finding)
}

// GlobalRecordVerifyResult 回写命中验证结论（valid/invalid/restricted/unverifiable）。
func (h *GitHubLeakAdminHandler) GlobalRecordVerifyResult(c *gin.Context) {
	var req struct {
		VerifyStatus   string `json:"verify_status" binding:"required"`
		VerifyEvidence string `json:"verify_evidence"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法（需要 verify_status 字段）")
		return
	}
	svc := h.leak(c)
	if svc == nil {
		return
	}
	if err := svc.RecordVerifyResult(c.Request.Context(), c.Param("fid"),
		strings.TrimSpace(req.VerifyStatus), strings.TrimSpace(req.VerifyEvidence)); err != nil {
		if errors.Is(err, githubleak.ErrNotFound) {
			utils.NotFound(c, "命中记录不存在")
			return
		}
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已回写", gin.H{"verify_status": req.VerifyStatus})
}

// silenceFalsePositive 标记误报后按指纹前缀自动建抑制规则（项目级 / 全局处置共用）。
// 同一密钥值再被扫到会直接静默；副作用失败不阻断处置，只记日志。
func silenceFalsePositive(c *gin.Context, svc *githubleak.Service, finding githubleak.Finding) {
	if finding.Fingerprint == "" {
		return
	}
	fp := finding.Fingerprint
	if len(fp) > 16 {
		fp = fp[:16]
	}
	if _, err := svc.AddSuppression(c.Request.Context(),
		githubleak.SuppressionFingerprintPrefix, fp, "标记误报自动静默", sessionUser(c)); err != nil {
		log.Printf("[GitHubLeak] 误报自动抑制创建失败 finding=%s: %v", finding.ID, err)
	}
}

// sessionUser 从 gin 上下文取当前用户名（审计/抑制 createdBy 用），取不到回 "system"。
func sessionUser(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	if v := c.GetHeader("X-User"); v != "" {
		return v
	}
	return "system"
}
