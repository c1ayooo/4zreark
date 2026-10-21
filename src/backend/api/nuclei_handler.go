package api

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/scanner/vulnscan"
	"github.com/c1ayooo/4zreark/scanner/vulnscan/nuclei"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// NucleiHandler Nuclei 处理器。
//
// 模板库只有一处：PG 的 pocs 表（与「POC 管理」是同一份数据）。
// 执行器按请求从库里构建 loader，不再扫描 config/nuclei-templates 目录。
type NucleiHandler struct {
	svc *service.NucleiService
}

// NewNucleiHandler 创建 Nuclei 处理器
func NewNucleiHandler() *NucleiHandler {
	return &NucleiHandler{svc: service.NewNucleiService()}
}

// GetTemplates 获取模板列表
// @Summary 获取 Nuclei 模板列表
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param severity query string false "严重程度过滤"
// @Param tags query string false "标签过滤"
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates [get]
func (h *NucleiHandler) GetTemplates(c *gin.Context) {
	severity := c.Query("severity")
	keyword := c.Query("keyword")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 20
	}

	var tags []string
	if raw := c.Query("tags"); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
			}
		}
	}

	items, total, err := h.svc.ListTemplates(repo.POCFilter{
		Type:     "nuclei",
		Severity: severity,
		Tags:     tags,
		Keyword:  keyword,
		Page:     page,
		PageSize: size,
	})
	if err != nil {
		utils.InternalError(c, "查询模板失败: "+err.Error())
		return
	}

	out := make([]map[string]interface{}, 0, len(items))
	for _, p := range items {
		out = append(out, map[string]interface{}{
			"id":          p.TemplateID,
			"poc_id":      p.ID.Hex(),
			"name":        p.Name,
			"author":      p.Author,
			"severity":    p.Severity,
			"description": p.Description,
			"tags":        strings.Join(p.Tags, ","),
			"cve_id":      strings.Join(p.CVEID, ","),
			"enabled":     p.Enabled,
			"source":      p.Source,
			"updated_at":  p.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "success",
		Data: map[string]interface{}{
			"items": out,
			"total": total,
			"page":  page,
			"size":  size,
		},
	})
}

// GetTemplate 获取单个模板详情
// @Summary 获取 Nuclei 模板详情
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param id path string true "模板ID"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates/{id} [get]
func (h *NucleiHandler) GetTemplate(c *gin.Context) {
	p, err := h.svc.GetTemplate(c.Param("id"))
	if err != nil {
		utils.NotFound(c, "Template not found")
		return
	}

	// 顺带返回解析后的模板结构，前端不必自己再解析 YAML。
	var tpl *nuclei.NucleiTemplate
	if t, err := h.svc.LoadTemplateByID(p.TemplateID); err == nil {
		tpl = t
	}
	utils.Success(c, map[string]interface{}{
		"poc":      p,
		"template": tpl,
	})
}

// GetTags 获取所有模板标签
// @Summary 获取所有 Nuclei 模板标签
// @Tags Nuclei
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/nuclei/tags [get]
func (h *NucleiHandler) GetTags(c *gin.Context) {
	tags, err := h.svc.Tags()
	if err != nil {
		utils.InternalError(c, "查询标签失败: "+err.Error())
		return
	}
	utils.Success(c, tags)
}

// GetStatistics 获取模板统计
// @Summary 获取 Nuclei 模板统计
// @Tags Nuclei
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/nuclei/statistics [get]
func (h *NucleiHandler) GetStatistics(c *gin.Context) {
	st, err := h.svc.Statistics()
	if err != nil {
		utils.InternalError(c, "统计失败: "+err.Error())
		return
	}
	utils.Success(c, map[string]interface{}{
		"total":       st.Total,
		"enabled":     st.Enabled,
		"by_severity": st.BySeverity,
		"by_type":     st.ByType,
	})
}

// ScanTarget 扫描目标
// @Summary 使用 Nuclei 模板扫描目标
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param request body NucleiScanRequest true "扫描请求"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/scan [post]
func (h *NucleiHandler) ScanTarget(c *gin.Context) {
	var req struct {
		Target      string   `json:"target" binding:"required"`
		TemplateIDs []string `json:"template_ids,omitempty"`
		Tags        []string `json:"tags,omitempty"`
		Severity    string   `json:"severity,omitempty"`
		Timeout     int      `json:"timeout,omitempty"` // seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "zre-nuclei-*")
	if err != nil {
		utils.InternalError(c, "创建模板目录失败: "+err.Error())
		return
	}
	defer os.RemoveAll(dir)

	var severities []string
	if req.Severity != "" {
		for _, s := range strings.Split(req.Severity, ",") {
			if s = strings.TrimSpace(s); s != "" {
				severities = append(severities, s)
			}
		}
	}

	count, err := h.svc.MaterializeTemplates(dir, severities, req.TemplateIDs, req.Tags)
	if err != nil {
		utils.InternalError(c, "加载模板失败: "+err.Error())
		return
	}
	if count == 0 {
		utils.BadRequest(c, "没有可用模板：库为空、全部未验证，或筛选条件过窄（可显式指定 template_ids）")
		return
	}

	scanner := vulnscan.NewNucleiCLIScanner(dir)
	if !scanner.IsAvailable() {
		utils.InternalError(c, "nuclei CLI 不可用")
		return
	}

	results, err := scanner.Scan(ctx, []string{req.Target}, &vulnscan.NucleiScanConfig{
		Concurrency: 25,
		RateLimit:   150,
		Timeout:     timeout,
	})
	if err != nil {
		utils.InternalError(c, "扫描失败: "+err.Error())
		return
	}

	utils.Success(c, map[string]interface{}{
		"target":        req.Target,
		"templates":     count,
		"total_scanned": count,
		"matched":       len(results),
		"results":       results,
	})
}

// UploadTemplate 上传模板
// @Summary 上传 Nuclei 模板
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param content body string true "模板YAML内容"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates [post]
func (h *NucleiHandler) UploadTemplate(c *gin.Context) {
	var req struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	poc, err := h.svc.UpsertTemplate([]byte(req.Content))
	if err != nil {
		utils.BadRequest(c, "模板解析或保存失败: "+err.Error())
		return
	}

	utils.SuccessWithMessage(c, "模板已保存到 POC 库", map[string]interface{}{
		"id":       poc.TemplateID,
		"poc_id":   poc.ID.Hex(),
		"name":     poc.Name,
		"severity": poc.Severity,
	})
}

// DeleteTemplate 删除模板
// @Summary 删除 Nuclei 模板
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param id path string true "模板ID"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates/{id} [delete]
func (h *NucleiHandler) DeleteTemplate(c *gin.Context) {
	if err := h.svc.DeleteTemplate(c.Param("id")); err != nil {
		utils.NotFound(c, "Template not found")
		return
	}
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// ReloadTemplates 重新加载模板
// @Summary 重新加载 Nuclei 模板
// @Tags Nuclei
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/nuclei/reload [post]
func (h *NucleiHandler) ReloadTemplates(c *gin.Context) {
	// 数据在 PG 里，不存在「重新扫盘」这一步；返回当前可用条数即可。
	st, err := h.svc.Statistics()
	if err != nil {
		utils.InternalError(c, "读取模板数失败: "+err.Error())
		return
	}
	utils.SuccessWithMessage(c, "模板库已是最新（数据源为 PG）", map[string]interface{}{
		"count": st.Total,
	})
}

// ValidateTemplate 验证模板
// @Summary 验证 Nuclei 模板语法
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param content body string true "模板YAML内容"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/validate [post]
func (h *NucleiHandler) ValidateTemplate(c *gin.Context) {
	var req struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	poc, tpl, err := h.svc.Validate([]byte(req.Content))
	if err != nil {
		c.JSON(http.StatusOK, utils.Response{
			Code:    0,
			Message: "success",
			Data: map[string]interface{}{
				"valid": false,
				"error": err.Error(),
			},
		})
		return
	}

	utils.Success(c, map[string]interface{}{
		"valid":    true,
		"id":       tpl.ID,
		"name":     tpl.Info.Name,
		"severity": tpl.Info.Severity,
		"tags":     tpl.Info.Tags,
		"poc_id":   poc.ID.Hex(),
	})
}
