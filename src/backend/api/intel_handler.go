package api

import (
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// IntelHandler 情报（9 个公开漏洞源）的 REST 面。
type IntelHandler struct {
	intelService *service.IntelService
}

func NewIntelHandler() *IntelHandler {
	return &IntelHandler{intelService: service.NewIntelService()}
}

// 合法档位，与 vulnerabilities.severity 的 CHECK 约束同一套。
var validIntelSeverity = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

// ListIntel 情报列表
// @Summary 漏洞情报列表
// @Tags vuln-intel
// @Produce json
// @Param severity query string false "critical|high|medium|low|info"
// @Param source_name query string false "源键，如 threatbook / chaitin"
// @Param cve query string false "CVE 编号"
// @Param q query string false "关键字（标题/描述模糊匹配）"
// @Param page query int false "页码"
// @Param page_size query int false "每页条数（上限 500）"
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel [get]
func (h *IntelHandler) ListIntel(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 20
	}

	severity := c.Query("severity")
	if severity != "" && !validIntelSeverity[severity] {
		utils.BadRequest(c, "severity 只能是 critical/high/medium/low/info")
		return
	}

	items, total, err := h.intelService.ListIntel(repo.IntelFilter{
		Severity:   severity,
		SourceName: c.Query("source_name"),
		CVE:        c.Query("cve"),
		Keyword:    c.Query("q"),
		Page:       page,
		PageSize:   pageSize,
	})
	if err != nil {
		utils.InternalError(c, "查询情报失败: "+err.Error())
		return
	}

	out := make([]gin.H, 0, len(items))
	for _, it := range items {
		out = append(out, intelRowJSON(it))
	}
	utils.SuccessWithPagination(c, out, total, page, pageSize)
}

// GetIntel 单条情报
// @Summary 情报详情
// @Tags vuln-intel
// @Produce json
// @Param unique_key path string true "unique_key"
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel/{unique_key} [get]
func (h *IntelHandler) GetIntel(c *gin.Context) {
	it, err := h.intelService.GetIntel(c.Param("unique_key"))
	if err != nil {
		utils.NotFound(c, "情报不存在")
		return
	}
	utils.Success(c, intelRowJSON(it))
}

// Stats 情报统计
// @Summary 情报统计
// @Tags vuln-intel
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel/stats [get]
func (h *IntelHandler) Stats(c *gin.Context) {
	stats, err := h.intelService.IntelStats()
	if err != nil {
		utils.InternalError(c, "统计失败: "+err.Error())
		return
	}
	utils.Success(c, stats)
}

// Poll 手动触发一轮轮询（同步等结果）
// @Summary 手动触发一轮情报轮询
// @Tags vuln-intel
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel/poll [post]
func (h *IntelHandler) Poll(c *gin.Context) {
	// 轮询一轮最长 5 分钟（9 个源里 5 个是网页抓取）。这个调用会占住一个
	// HTTP 连接，前端需要等；不适合放进页面自动刷新里。
	res, err := h.intelService.PollNow()
	if err != nil {
		utils.InternalError(c, "轮询失败: "+err.Error())
		return
	}

	errorsOut := make([]gin.H, 0, len(res.Errors))
	for _, e := range res.Errors {
		errorsOut = append(errorsOut, gin.H{"source": e.Source, "error": e.Error})
	}
	utils.Success(c, gin.H{
		"new":      res.New,
		"updated":  res.Updated,
		"failed":   res.Failed,
		"sources":  res.Sources,
		"errors":   errorsOut,
		"new_high": res.NewHigh,
	})
}

// GetSettings 读情报设置与轮询状态
// @Summary 情报设置
// @Tags vuln-intel
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel/settings [get]
func (h *IntelHandler) GetSettings(c *gin.Context) {
	out, err := h.intelService.GetSettings()
	if err != nil {
		utils.InternalError(c, "读取设置失败: "+err.Error())
		return
	}
	utils.Success(c, out)
}

// UpdateSettings 改情报设置
// @Summary 更新情报设置
// @Tags vuln-intel
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel/settings [put]
func (h *IntelHandler) UpdateSettings(c *gin.Context) {
	var in map[string]any
	if err := c.ShouldBindJSON(&in); err != nil {
		utils.BadRequest(c, "请求体不是合法 JSON")
		return
	}
	// 只接受白名单里的键，未知键静默忽略——设置表里还有其他模块的行。
	want := []string{"vulnintel.enabled", "vulnintel.interval_minutes", "vulnintel.notify_enabled"}
	accepted := make(map[string]any, len(want))
	for _, k := range want {
		if v, ok := in[k]; ok {
			accepted[k] = v
		}
	}
	if len(accepted) == 0 {
		utils.BadRequest(c, "没有可用的设置项")
		return
	}

	if err := h.intelService.UpdateSettings(accepted); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	out, err := h.intelService.GetSettings()
	if err != nil {
		utils.SuccessWithMessage(c, "设置已保存", nil)
		return
	}
	utils.Success(c, out)
}

// intelRowJSON 把一行转成响应体。enriched_at 为 NULL 时不输出空字符串。
func intelRowJSON(it *repo.IntelRow) gin.H {
	out := gin.H{
		"id":          it.ID,
		"unique_key":  it.UniqueKey,
		"title":       it.Title,
		"description": it.Description,
		"severity":    it.Severity,
		"cve":         it.CVE,
		"disclosure":  it.Disclosure,
		"solutions":   it.Solutions,
		"source":      it.Source,
		"source_name": it.SourceName,
		"source_url":  it.SourceURL,
		"tags":        it.Tags,
		"references":  it.References,
		"created_at":  it.CreatedAt,
		"updated_at":  it.UpdatedAt,
		"lab_only":    it.LabOnly,
	}
	if !it.EnrichedAt.IsZero() {
		out["enriched_at"] = it.EnrichedAt
		out["has_poc"] = len(it.GithubPoc) > 0
		out["cvss_score"] = it.CVSSScore
		out["cvss_vector"] = it.CVSSVector
		out["cwes"] = it.CWEs
		out["affected"] = it.Affected
		out["github_poc"] = it.GithubPoc
	}
	return out
}

// Enrich 对单条情报做 GitHub PoC 检索与分诊
// @Summary 富化一条情报（GitHub PoC + GHSA + 分诊）
// @Tags vuln-intel
// @Produce json
// @Param unique_key path string true "unique_key"
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel/{unique_key}/enrich [post]
func (h *IntelHandler) Enrich(c *gin.Context) {
	key := c.Param("unique_key")
	res, err := h.intelService.EnrichIntel(key)
	if err != nil {
		// 「不存在」和「没 CVE」是业务拒绝，不是服务端故障。
		msg := err.Error()
		switch {
		case strings.Contains(msg, "不存在"),
			strings.Contains(msg, "没有 CVE"),
			strings.Contains(msg, "GitHub Token"):
			utils.BadRequest(c, msg)
		default:
			utils.InternalError(c, "富化失败: "+msg)
		}
		return
	}
	utils.Success(c, gin.H{
		"cve":         res.CVE,
		"poc_count":   len(res.POCs),
		"pocs":        res.POCs,
		"cvss_score":  res.CVSSScore,
		"cvss_vector": res.CVSSVector,
		"cwes":        res.CWEs,
		"affected":    res.Affected,
		"lab_only":    res.LabOnly,
	})
}

// EnrichStatus 查看某条情报的富化状态
// @Summary 情报富化状态
// @Tags vuln-intel
// @Produce json
// @Param unique_key path string true "unique_key"
// @Success 200 {object} map[string]interface{}
// @Router /api/vuln-intel/{unique_key}/enrich [get]
func (h *IntelHandler) EnrichStatus(c *gin.Context) {
	out, err := h.intelService.EnrichStatus(c.Param("unique_key"))
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	utils.Success(c, out)
}
