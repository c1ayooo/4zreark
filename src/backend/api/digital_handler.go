package api

import (
	"encoding/base64"
	"errors"
	"io"
	"mime/multipart"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// DigitalHandler 数字资产名单与本地文档导入（v4 §14）。
// 名单与站点库解耦；文档只解析文本，不重放请求。
type DigitalHandler struct {
	digital  *service.DigitalService
	localdoc *service.LocalDocService
}

func NewDigitalHandler() *DigitalHandler {
	return &DigitalHandler{
		digital:  service.NewDigitalService(),
		localdoc: service.NewLocalDocService(),
	}
}

// ListDigitalAssets GET /api/digital-assets?project_id=&kind=&q=&page=&page_size=
func (h *DigitalHandler) ListDigitalAssets(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	items, total, err := h.digital.List(c.Request.Context(), repo.DigitalFilter{
		ProjectID: projectID,
		Kind:      c.Query("kind"),
		Query:     c.Query("q"),
		Page:      page,
		PageSize:  pageSize,
	})
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithPagination(c, items, total, page, pageSize)
}

// DeleteDigitalAsset DELETE /api/digital-assets/:id
func (h *DigitalHandler) DeleteDigitalAsset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法名单 ID")
		return
	}
	if err := h.digital.Delete(c.Request.Context(), id); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "名单不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已删除", nil)
}

type digitalPreviewBody struct {
	ProjectID int64    `json:"project_id"`
	Kind      string   `json:"kind"`
	Names     []string `json:"names"`
	Text      string   `json:"text"`
	Company   string   `json:"company"`
	Platform  string   `json:"platform"`
	Source    string   `json:"source"`
}

// PreviewDigitalAssets POST /api/digital-assets/preview
func (h *DigitalHandler) PreviewDigitalAssets(c *gin.Context) {
	var body digitalPreviewBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	names := body.Names
	if strings.TrimSpace(body.Text) != "" {
		names = append(names, service.NamesFromText(body.Text)...)
	}
	preview, err := h.digital.Preview(c.Request.Context(), body.ProjectID, body.Kind,
		names, body.Company, body.Platform, body.Source)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, preview)
}

type tokenBody struct {
	Token string `json:"token"`
	Kind  string `json:"kind"`
}

// CommitDigitalImport POST /api/digital-assets/commit
func (h *DigitalHandler) CommitDigitalImport(c *gin.Context) {
	var body tokenBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	batch, inserted, err := h.digital.Commit(c.Request.Context(), body.Token, c.GetString("username"))
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "名单已导入", gin.H{
		"batch": batch, "inserted": inserted,
	})
}

// ListImportBatches GET /api/digital-imports?project_id=&limit=
func (h *DigitalHandler) ListImportBatches(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	items, err := h.digital.Batches(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}

// UndoImportBatch POST /api/digital-imports/undo
func (h *DigitalHandler) UndoImportBatch(c *gin.Context) {
	var body struct {
		BatchID int64 `json:"batch_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.BatchID <= 0 {
		utils.BadRequest(c, "batch_id 必填")
		return
	}
	deleted, err := h.digital.Undo(c.Request.Context(), body.BatchID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "回执不存在或已撤销")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已撤销本批次新增名单", gin.H{"deleted": deleted})
}

// CancelPreview POST /api/digital-imports/cancel
func (h *DigitalHandler) CancelPreview(c *gin.Context) {
	var body tokenBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	cancelled := false
	if body.Kind == "local_doc" {
		cancelled = service.CancelLocalDocPreview(body.Token)
	} else {
		cancelled = service.CancelDigitalPreview(body.Token)
	}
	utils.Success(c, gin.H{"cancelled": cancelled})
}

// PreviewLocalDocument POST /api/local-documents/preview
// 支持 multipart（file + project_id）与 JSON（project_id/filename/content|content_base64）。
func (h *DigitalHandler) PreviewLocalDocument(c *gin.Context) {
	if strings.HasPrefix(c.ContentType(), "multipart/form-data") {
		h.previewLocalDocMultipart(c)
		return
	}
	var body struct {
		ProjectID     int64  `json:"project_id"`
		Filename      string `json:"filename"`
		Content       string `json:"content"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	data := []byte(body.Content)
	if body.ContentBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(body.ContentBase64)
		if err != nil {
			utils.BadRequest(c, "content_base64 解码失败")
			return
		}
		data = decoded
	}
	h.finishLocalDocPreview(c, body.ProjectID, body.Filename, data)
}

func (h *DigitalHandler) previewLocalDocMultipart(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.PostForm("project_id"), 10, 64)
	file, err := c.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "缺少 file")
		return
	}
	data, err := readUpload(file)
	if err != nil {
		if errors.Is(err, service.ErrLocalDocTooLarge) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.BadRequest(c, "读取文件失败: "+err.Error())
		return
	}
	h.finishLocalDocPreview(c, projectID, file.Filename, data)
}

func (h *DigitalHandler) finishLocalDocPreview(c *gin.Context, projectID int64, filename string, data []byte) {
	preview, err := h.localdoc.Preview(c.Request.Context(), projectID, filename, data)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.Success(c, preview)
}

func readUpload(file *multipart.FileHeader) ([]byte, error) {
	if file.Size > service.MaxLocalDocBytes {
		return nil, service.ErrLocalDocTooLarge
	}
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, service.MaxLocalDocBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > service.MaxLocalDocBytes {
		return nil, service.ErrLocalDocTooLarge
	}
	return data, nil
}

// ImportLocalDocument POST /api/local-documents/import
func (h *DigitalHandler) ImportLocalDocument(c *gin.Context) {
	var body tokenBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	res, err := h.localdoc.Commit(c.Request.Context(), body.Token, c.GetString("username"))
	if err != nil {
		if errors.Is(err, service.ErrLocalDocPreviewExpired) {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "文档已导入", res)
}
