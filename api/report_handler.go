package api

import (
	"errors"
	"os"
	"strings"

	"github.com/c1ayooo/4zreark/report"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// ReportHandler 报告生成与下载。报告的排版/渲染在 report 包，
// 本层只负责参数校验、取数与文件回传。
type ReportHandler struct {
	reportService *service.ReportService
}

func NewReportHandler() *ReportHandler {
	return &ReportHandler{reportService: service.NewReportService()}
}

// GenerateReport 生成报告（html / pdf / markdown）
// @Summary 生成安全评估报告
// @Tags reports
// @Accept json
// @Produce json
// @Router /api/reports/generate [post]
func (h *ReportHandler) GenerateReport(c *gin.Context) {
	var req service.ReportGenInput
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if uid, ok := c.Get("user_id"); ok {
		if s, ok := uid.(string); ok {
			req.CreatedBy = s
		}
	}
	rep, err := h.reportService.Generate(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, report.ErrInvalidRequest) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.InternalError(c, "生成报告失败: "+err.Error())
		return
	}
	utils.SuccessWithMessage(c, "报告已生成", gin.H{
		"id": rep.ID.Hex(), "name": rep.Name, "type": rep.Type,
		"report_kind": rep.ReportKind, "template": rep.Template,
		"file_path": rep.FilePath, "summary": rep.Summary,
	})
}

// ListTemplates 列出内置报告模板（人工选择模板、前端展示说明用）。
// @Summary 报告模板目录
// @Tags reports
// @Router /api/reports/templates [get]
func (h *ReportHandler) ListTemplates(c *gin.Context) {
	all := report.ListProfiles()
	kind := strings.ToLower(strings.TrimSpace(c.Query("kind")))
	if kind != "" {
		filtered := make([]report.Profile, 0, len(all))
		for _, p := range all {
			if p.Type == kind {
				filtered = append(filtered, p)
			}
		}
		all = filtered
	}
	utils.Success(c, gin.H{"items": all, "total": len(all)})
}

// DownloadReport 下载报告文件
// @Summary 下载报告文件
// @Tags reports
// @Param id path string true "报告 ID"
// @Router /api/reports/{id}/download [get]
func (h *ReportHandler) DownloadReport(c *gin.Context) {
	path, rep, err := h.reportService.GetFilePath(c.Request.Context(), c.Param("id"))
	if err != nil {
		utils.NotFound(c, "报告不存在或文件未生成")
		return
	}
	if _, err := os.Stat(path); err != nil {
		utils.NotFound(c, "报告文件不存在")
		return
	}
	name := strings.TrimSpace(rep.Name)
	if name == "" {
		name = "report"
	}
	ext := ".html"
	switch strings.ToLower(rep.Type) {
	case "pdf":
		ext = ".pdf"
	case "markdown", "md":
		ext = ".md"
	case "docx", "word":
		ext = ".docx"
	case "xlsx", "excel":
		ext = ".xlsx"
	}
	c.FileAttachment(path, name+ext)
}
