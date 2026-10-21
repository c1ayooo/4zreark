package api

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/gin-gonic/gin"
)

type PluginHandler struct {
	pluginService *service.PluginService
}

func NewPluginHandler() *PluginHandler {
	return &PluginHandler{
		pluginService: service.NewPluginService(),
	}
}

// ListPlugins lists plugins with filtering and pagination
// GET /api/plugins
func (h *PluginHandler) ListPlugins(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	pluginType := c.Query("type")
	language := c.Query("language")
	keyword := c.Query("keyword")
	enabledStr := c.Query("enabled")

	var enabled *bool
	if enabledStr != "" {
		b := enabledStr == "true"
		enabled = &b
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	plugins, total, err := h.pluginService.ListPlugins(pluginType, language, enabled, keyword, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, plugins, total, page, pageSize)
}

// GetPlugin gets a single plugin by ID
// GET /api/plugins/:id
func (h *PluginHandler) GetPlugin(c *gin.Context) {
	pluginID := c.Param("id")

	plugin, err := h.pluginService.GetPluginByID(pluginID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}

	utils.Success(c, plugin)
}

// CreatePlugin creates a new plugin
// POST /api/plugins
func (h *PluginHandler) CreatePlugin(c *gin.Context) {
	var req struct {
		Name         string                 `json:"name" binding:"required"`
		Description  string                 `json:"description"`
		Author       string                 `json:"author"`
		Version      string                 `json:"version"`
		Type         string                 `json:"type" binding:"required"`
		Language     string                 `json:"language" binding:"required"`
		EntryFile    string                 `json:"entry_file"`
		Config       map[string]interface{} `json:"config"`
		Dependencies []string               `json:"dependencies"`
		Tags         []string               `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	plugin := &models.Plugin{
		Name:         req.Name,
		Description:  req.Description,
		Author:       req.Author,
		Version:      req.Version,
		Type:         req.Type,
		Language:     req.Language,
		EntryFile:    req.EntryFile,
		Config:       req.Config,
		Dependencies: req.Dependencies,
		Tags:         req.Tags,
		Source:       "custom",
	}

	if plugin.Version == "" {
		plugin.Version = "1.0.0"
	}

	if err := h.pluginService.CreatePlugin(plugin); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": plugin.ID.Hex()})
}

// UpdatePlugin updates a plugin
// PUT /api/plugins/:id
func (h *PluginHandler) UpdatePlugin(c *gin.Context) {
	pluginID := c.Param("id")

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	// Remove protected fields
	delete(req, "id")
	delete(req, "_id")
	delete(req, "created_at")

	if err := h.pluginService.UpdatePlugin(pluginID, req); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeletePlugin deletes a plugin
// DELETE /api/plugins/:id
func (h *PluginHandler) DeletePlugin(c *gin.Context) {
	pluginID := c.Param("id")

	if err := h.pluginService.DeletePlugin(pluginID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}

// TogglePlugin enables or disables a plugin
// PUT /api/plugins/:id/toggle
func (h *PluginHandler) TogglePlugin(c *gin.Context) {
	pluginID := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.pluginService.TogglePlugin(pluginID, req.Enabled); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "状态更新成功", nil)
}

// InstallPlugin installs a plugin
// POST /api/plugins/:id/install
func (h *PluginHandler) InstallPlugin(c *gin.Context) {
	pluginID := c.Param("id")

	if err := h.pluginService.InstallPlugin(pluginID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "安装成功", nil)
}

// UninstallPlugin uninstalls a plugin
// POST /api/plugins/:id/uninstall
func (h *PluginHandler) UninstallPlugin(c *gin.Context) {
	pluginID := c.Param("id")

	if err := h.pluginService.UninstallPlugin(pluginID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "卸载成功", nil)
}

// ListFingerprintRules lists fingerprint rules
// GET /api/fingerprints
func (h *PluginHandler) ListFingerprintRules(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	category := c.Query("category")
	keyword := c.Query("keyword")

	rules, total, err := h.pluginService.ListFingerprintRules(category, keyword, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, rules, total, page, pageSize)
}

// CreateFingerprintRule creates a fingerprint rule
// POST /api/fingerprints
func (h *PluginHandler) CreateFingerprintRule(c *gin.Context) {
	var req struct {
		Name     string                    `json:"name" binding:"required"`
		Category string                    `json:"category" binding:"required"`
		Version  string                    `json:"version"`
		Rules    []models.FingerprintMatch `json:"rules" binding:"required"`
		Source   string                    `json:"source"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	rule := &models.FingerprintRule{
		Name:     req.Name,
		Category: req.Category,
		Version:  req.Version,
		Rules:    req.Rules,
		Source:   req.Source,
	}

	if rule.Source == "" {
		rule.Source = "custom"
	}

	if err := h.pluginService.CreateFingerprintRule(rule); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": rule.ID.Hex()})
}

// DeleteFingerprintRule deletes a fingerprint rule
// DELETE /api/fingerprints/:id
func (h *PluginHandler) DeleteFingerprintRule(c *gin.Context) {
	ruleID := c.Param("id")

	if err := h.pluginService.DeleteFingerprintRule(ruleID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}

// ListDictionaries lists dictionaries
// GET /api/dictionaries
func (h *PluginHandler) ListDictionaries(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	dictType := c.Query("type")

	dicts, total, err := h.pluginService.ListDictionaries(dictType, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}

	utils.SuccessWithPagination(c, dicts, total, page, pageSize)
}

// CreateDictionary creates a dictionary
// POST /api/dictionaries
func (h *PluginHandler) CreateDictionary(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		Name        string `json:"name" binding:"required"`
		Type        string `json:"type" binding:"required"`
		Description string `json:"description"`
		FilePath    string `json:"file_path" binding:"required"`
		LineCount   int    `json:"line_count"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	dict := &models.Dictionary{
		Name:        req.Name,
		Type:        req.Type,
		Description: req.Description,
		FilePath:    req.FilePath,
		LineCount:   req.LineCount,
		IsBuiltin:   false,
	}

	if userID != nil {
		uid, _ := oid.ObjectIDFromHex(userID.(string))
		dict.CreatedBy = uid
	}

	if err := h.pluginService.CreateDictionary(dict); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": dict.ID.Hex()})
}

// DeleteDictionary deletes a dictionary
// DELETE /api/dictionaries/:id
// PreviewDictionary 两段式导入第一步：解析/去重/分段，不落库。
// 支持 text / csv / tsv（text 字段）与 xlsx（content_base64，取第一列）。
// POST /api/dictionaries/preview
func (h *PluginHandler) PreviewDictionary(c *gin.Context) {
	var body struct {
		Name          string `json:"name" binding:"required"`
		Type          string `json:"type" binding:"required"`
		Text          string `json:"text"`
		Format        string `json:"format"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "参数错误：需要 name/type，以及 text 或 content_base64")
		return
	}
	format := strings.ToLower(strings.TrimSpace(body.Format))
	if format == "xlsx" || format == "xls" || body.ContentBase64 != "" {
		if format == "xls" {
			utils.BadRequest(c, "旧版 .xls 暂不支持，请另存为 .xlsx 或 CSV")
			return
		}
		data, derr := base64.StdEncoding.DecodeString(body.ContentBase64)
		if derr != nil {
			utils.BadRequest(c, "content_base64 解码失败")
			return
		}
		preview, err := h.pluginService.PreviewDictionaryXLSX(body.Name, body.Type, data)
		if err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
		utils.SuccessWithMessage(c, "预览已生成，15 分钟内有效", preview)
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		utils.BadRequest(c, "text 或 content_base64 必填")
		return
	}
	preview, err := h.pluginService.PreviewDictionaryFormatted(body.Name, body.Type, body.Text, body.Format)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "预览已生成，15 分钟内有效", preview)
}

// ImportDictionary 两段式导入第二步：消费 token，创建字典并物化条目。
// POST /api/dictionaries/import
func (h *PluginHandler) ImportDictionary(c *gin.Context) {
	var body struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "缺少预览 token")
		return
	}
	dict, inserted, err := h.pluginService.ImportDictionary(c.Request.Context(), body.Token)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "字典已导入", gin.H{"dictionary": dict, "entries": inserted})
}

// ListDictionaryEntries 分页读取词表条目（segment=0 表示全部段）。
// GET /api/dictionaries/:id/entries?segment=&page=&page_size=
func (h *PluginHandler) ListDictionaryEntries(c *gin.Context) {
	segment, _ := strconv.Atoi(c.DefaultQuery("segment", "0"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	values, total, err := h.pluginService.ListDictionaryEntries(c.Request.Context(), c.Param("id"), segment, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithPagination(c, values, total, page, pageSize)
}

func (h *PluginHandler) DeleteDictionary(c *gin.Context) {
	dictID := c.Param("id")

	if err := h.pluginService.DeleteDictionary(dictID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}
