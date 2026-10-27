package api

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/gin-gonic/gin"
)

type VulnHandler struct {
	vulnService *service.VulnService
}

func NewVulnHandler() *VulnHandler {
	return &VulnHandler{
		vulnService: service.NewVulnService(),
	}
}

// ListVulnerabilities lists vulnerabilities with filtering and pagination
// GET /api/vulnerabilities
func (h *VulnHandler) ListVulnerabilities(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	workspaceID := c.Query("workspace_id")
	severity := c.Query("severity")
	status := c.Query("status")
	keyword := c.Query("keyword")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	vulns, total, err := h.vulnService.ListVulnerabilities(workspaceID, severity, status, keyword, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, vulns, total, page, pageSize)
}

// GetVulnerability gets a single vulnerability by ID
// GET /api/vulnerabilities/:id
func (h *VulnHandler) GetVulnerability(c *gin.Context) {
	vulnID := c.Param("id")

	vuln, err := h.vulnService.GetVulnByID(vulnID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}

	utils.Success(c, vuln)
}

// CreateVulnerability creates a new vulnerability
// POST /api/vulnerabilities
func (h *VulnHandler) CreateVulnerability(c *gin.Context) {
	var req struct {
		WorkspaceID string              `json:"workspace_id"`
		AssetID     string              `json:"asset_id"`
		TaskID      string              `json:"task_id"`
		Name        string              `json:"name" binding:"required"`
		Description string              `json:"description"`
		Severity    models.VulnSeverity `json:"severity" binding:"required"`
		Type        string              `json:"type"`
		Target      string              `json:"target" binding:"required"`
		Method      string              `json:"method"`
		Payload     string              `json:"payload"`
		Evidence    string              `json:"evidence"`
		Request     string              `json:"request"`
		Response    string              `json:"response"`
		CVEID       []string            `json:"cve_id"`
		References  []string            `json:"references"`
		Solution    string              `json:"solution"`
		Tags        []string            `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if bad := firstUnsafeReference(req.References); bad != "" {
		utils.BadRequest(c, "参考链接只允许 http/https 协议: "+bad)
		return
	}

	vuln := &models.Vulnerability{
		Name:        req.Name,
		Description: req.Description,
		Severity:    req.Severity,
		Type:        req.Type,
		Target:      req.Target,
		Method:      req.Method,
		Payload:     req.Payload,
		Evidence:    req.Evidence,
		Request:     req.Request,
		Response:    req.Response,
		CVEID:       req.CVEID,
		References:  req.References,
		Solution:    req.Solution,
		Tags:        req.Tags,
		Scanner:     "manual",
	}

	if req.WorkspaceID != "" {
		wsID, _ := oid.ObjectIDFromHex(req.WorkspaceID)
		vuln.WorkspaceID = wsID
	}
	if req.AssetID != "" {
		assetID, _ := oid.ObjectIDFromHex(req.AssetID)
		vuln.AssetID = assetID
	}
	if req.TaskID != "" {
		taskID, _ := oid.ObjectIDFromHex(req.TaskID)
		vuln.TaskID = taskID
	}

	// 查重只报告不拦截：命中候选随创建结果一起返回，由人工裁决是否合并。
	duplicates, _ := h.vulnService.FindDuplicates(c.Request.Context(), vuln)

	if err := h.vulnService.CreateVulnerability(vuln); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": vuln.ID.Hex(), "duplicates": duplicates})
}

// UpdateVulnerability updates a vulnerability
// PUT /api/vulnerabilities/:id
func (h *VulnHandler) UpdateVulnerability(c *gin.Context) {
	vulnID := c.Param("id")

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	// Remove protected fields
	delete(req, "id")
	delete(req, "_id")
	delete(req, "created_at")

	if err := h.vulnService.UpdateVulnerability(vulnID, req); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeleteVulnerability deletes a vulnerability
// DELETE /api/vulnerabilities/:id
func (h *VulnHandler) DeleteVulnerability(c *gin.Context) {
	vulnID := c.Param("id")

	if err := h.vulnService.DeleteVulnerability(vulnID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}

// MarkVulnAsFixed marks a vulnerability as fixed
// PUT /api/vulnerabilities/:id/fixed
func (h *VulnHandler) MarkVulnAsFixed(c *gin.Context) {
	vulnID := c.Param("id")
	username, _ := c.Get("username")

	var req struct {
		FixedBy string `json:"fixed_by"`
	}
	c.ShouldBindJSON(&req)

	if req.FixedBy == "" && username != nil {
		req.FixedBy = username.(string)
	}

	if err := h.vulnService.MarkAsFixed(vulnID, req.FixedBy); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "已标记为已修复", nil)
}

// MarkVulnAsIgnored marks a vulnerability as ignored
// PUT /api/vulnerabilities/:id/ignore
func (h *VulnHandler) MarkVulnAsIgnored(c *gin.Context) {
	vulnID := c.Param("id")

	if err := h.vulnService.MarkAsIgnored(vulnID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "已标记为忽略", nil)
}

// MarkVulnAsFalsePositive marks a vulnerability as false positive
// PUT /api/vulnerabilities/:id/false-positive
func (h *VulnHandler) MarkVulnAsFalsePositive(c *gin.Context) {
	vulnID := c.Param("id")

	if err := h.vulnService.MarkAsFalsePositive(vulnID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "已标记为误报", nil)
}

// GetVulnStats returns vulnerability statistics
// GET /api/vulnerabilities/stats
func (h *VulnHandler) GetVulnStats(c *gin.Context) {
	workspaceID := c.Query("workspace_id")

	stats, err := h.vulnService.GetVulnStats(workspaceID)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.Success(c, stats)
}

// ListPOCs lists POCs with filtering and pagination
// GET /api/pocs
func (h *VulnHandler) ListPOCs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	pocType := c.Query("type")
	severity := c.Query("severity")
	keyword := c.Query("keyword")
	tagsStr := c.Query("tags")

	var tags []string
	if tagsStr != "" {
		tags = strings.Split(tagsStr, ",")
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	pocs, total, err := h.vulnService.ListPOCs(pocType, severity, tags, keyword, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, pocs, total, page, pageSize)
}

// GetPOC gets a single POC by ID
// GET /api/pocs/:id
func (h *VulnHandler) GetPOC(c *gin.Context) {
	pocID := c.Param("id")

	poc, err := h.vulnService.GetPOCByID(pocID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}

	utils.Success(c, poc)
}

// CreatePOC creates a new POC
// POST /api/pocs
func (h *VulnHandler) CreatePOC(c *gin.Context) {
	var req struct {
		Name        string              `json:"name" binding:"required"`
		Description string              `json:"description"`
		Author      string              `json:"author"`
		Severity    models.VulnSeverity `json:"severity" binding:"required"`
		Type        string              `json:"type" binding:"required"`
		Tags        []string            `json:"tags"`
		Content     string              `json:"content" binding:"required"`
		CVEID       []string            `json:"cve_id"`
		References  []string            `json:"references"`
		Source      string              `json:"source"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if bad := firstUnsafeReference(req.References); bad != "" {
		utils.BadRequest(c, "参考链接只允许 http/https 协议: "+bad)
		return
	}

	poc := &models.POC{
		Name:        req.Name,
		Description: req.Description,
		Author:      req.Author,
		Severity:    req.Severity,
		Type:        req.Type,
		Tags:        req.Tags,
		Content:     req.Content,
		CVEID:       req.CVEID,
		References:  req.References,
		Source:      req.Source,
		Version:     "1.0",
	}

	if poc.Source == "" {
		poc.Source = "custom"
	}

	if err := h.vulnService.CreatePOC(poc); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": poc.ID.Hex()})
}

// UpdatePOC updates a POC
// PUT /api/pocs/:id
func (h *VulnHandler) UpdatePOC(c *gin.Context) {
	pocID := c.Param("id")

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	// Remove protected fields
	delete(req, "id")
	delete(req, "_id")
	delete(req, "created_at")

	if err := h.vulnService.UpdatePOC(pocID, req); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeletePOC deletes a POC
// DELETE /api/pocs/:id
func (h *VulnHandler) DeletePOC(c *gin.Context) {
	pocID := c.Param("id")

	if err := h.vulnService.DeletePOC(pocID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}

// TogglePOC enables or disables a POC
// PUT /api/pocs/:id/toggle
func (h *VulnHandler) TogglePOC(c *gin.Context) {
	pocID := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.vulnService.TogglePOC(pocID, req.Enabled); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "状态更新成功", nil)
}

// ListReports lists vulnerability reports
// GET /api/reports
func (h *VulnHandler) ListReports(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	workspaceID := c.Query("workspace_id")

	reports, total, err := h.vulnService.ListReports(workspaceID, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, reports, total, page, pageSize)
}

// GetReport gets a report by ID
// GET /api/reports/:id
func (h *VulnHandler) GetReport(c *gin.Context) {
	reportID := c.Param("id")

	report, err := h.vulnService.GetReportByID(reportID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}

	utils.Success(c, report)
}

// CreateReport creates a vulnerability report
// POST /api/reports
func (h *VulnHandler) CreateReport(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		WorkspaceID string `json:"workspace_id"`
		Name        string `json:"name" binding:"required"`
		Type        string `json:"type" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	report := &models.VulnReport{
		Name: req.Name,
		Type: req.Type,
	}

	if req.WorkspaceID != "" {
		wsID, _ := oid.ObjectIDFromHex(req.WorkspaceID)
		report.WorkspaceID = wsID
	}

	if userID != nil {
		uid, _ := oid.ObjectIDFromHex(userID.(string))
		report.CreatedBy = uid
	}

	if err := h.vulnService.CreateReport(report); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": report.ID.Hex()})
}

// DeleteReport deletes a report
// DELETE /api/reports/:id
func (h *VulnHandler) DeleteReport(c *gin.Context) {
	reportID := c.Param("id")

	if err := h.vulnService.DeleteReport(reportID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}

// GetVulnStatistics 获取漏洞统计数据
// GET /api/vulnerabilities/statistics
func (h *VulnHandler) GetVulnStatistics(c *gin.Context) {
	workspaceID := c.Query("workspace_id")

	stats, err := h.vulnService.GetVulnStatistics(workspaceID)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.Success(c, stats)
}

// ReviewVuln 复核漏洞：流转状态 + 记录复核人/意见。
// POST /api/vulnerabilities/:id/review
func (h *VulnHandler) ReviewVuln(c *gin.Context) {
	vulnID := c.Param("id")
	username, _ := c.Get("username")

	var req struct {
		ToStatus models.VulnStatus `json:"to_status" binding:"required"`
		Note     string            `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	reviewer := ""
	if username != nil {
		reviewer, _ = username.(string)
	}
	vuln, review, err := h.vulnService.ReviewVuln(service.ReviewVulnInput{
		VulnID:   vulnID,
		ToStatus: req.ToStatus,
		Note:     req.Note,
		Reviewer: reviewer,
	})
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "复核已记录", gin.H{
		"vulnerability": vuln,
		"review":        review,
	})
}

// ListVulnReviews 复核历史（最早在前）。
// GET /api/vulnerabilities/:id/reviews
func (h *VulnHandler) ListVulnReviews(c *gin.Context) {
	reviews, err := h.vulnService.ListVulnReviews(c.Param("id"))
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": reviews, "total": len(reviews)})
}

// ReviewStats 复核分布统计。
// GET /api/vulnerabilities/review-stats
func (h *VulnHandler) ReviewStats(c *gin.Context) {
	stats, err := h.vulnService.ReviewStats(c.Query("workspace_id"))
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	utils.Success(c, stats)
}

// VerifyVulnerability 验证漏洞
// POST /api/vulnerabilities/:id/verify
func (h *VulnHandler) VerifyVulnerability(c *gin.Context) {
	vulnID := c.Param("id")

	vuln, verified, err := h.vulnService.VerifyVulnerability(vulnID)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.Success(c, gin.H{
		"vulnerability": vuln,
		"verified":      verified,
	})
}

// BatchUpdateVulnStatus 批量更新漏洞状态
// POST /api/vulnerabilities/batch-update
func (h *VulnHandler) BatchUpdateVulnStatus(c *gin.Context) {
	var req struct {
		VulnIDs []string          `json:"vuln_ids" binding:"required"`
		Status  models.VulnStatus `json:"status" binding:"required"`
		Note    string            `json:"note"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	// 批量也走复核通道：非法流转跳过、合法流转落复核记录，
	// 不再是无痕迹的裸 UPDATE。
	reviewer := ""
	if username, ok := c.Get("username"); ok {
		reviewer, _ = username.(string)
	}
	updated, skipped, err := h.vulnService.BatchReview(req.VulnIDs, req.Status, req.Note, reviewer)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	msg := fmt.Sprintf("复核成功 %d 条", updated)
	if skipped > 0 {
		msg += fmt.Sprintf("，跳过 %d 条（状态不允许流转或不存在）", skipped)
	}
	utils.SuccessWithMessage(c, msg, gin.H{"updated": updated, "skipped": skipped})
}

// GetVulnsByTask 获取任务的漏洞列表
// GET /api/tasks/:id/vulnerabilities
func (h *VulnHandler) GetVulnsByTask(c *gin.Context) {
	taskID := c.Param("id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))

	vulns, total, err := h.vulnService.GetVulnsByTaskID(taskID, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, vulns, total, page, pageSize)
}

// firstUnsafeReference 返回第一个协议不合规的参考链接（安全审计 M16）：
// 只放行 http/https，拒绝 javascript:/data: 等可执行协议的存储型 XSS 注入。
func firstUnsafeReference(refs []string) string {
	for _, r := range refs {
		trimmed := strings.TrimSpace(r)
		if trimmed == "" {
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return trimmed
		}
	}
	return ""
}
