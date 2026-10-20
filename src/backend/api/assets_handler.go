package api

import (
	"fmt"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// AssetHandler 是资产治理域（P0）的 HTTP 入口。
// P0 阶段直接调 repo，待 service 层补齐后再收口。
type AssetHandler struct {
	assets *repo.AssetRepo
}

func NewAssetHandler() *AssetHandler {
	return &AssetHandler{assets: repo.NewAssetRepo()}
}

// Overview 资产总览：原始记录与归并站点分开计数。
// GET /api/overview
func (h *AssetHandler) Overview(c *gin.Context) {
	o, err := h.assets.Overview(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, o)
}

// ListProjects 项目列表（资产归属边界）。
// GET /api/projects
func (h *AssetHandler) ListProjects(c *gin.Context) {
	ps, err := h.assets.ListProjects(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, ps)
}

// ListAssets 资产列表，支持 DSL 查询串 q。
// GET /api/assets?page=1&page_size=20&q=status_code="200"&&domain="example.com"
func (h *AssetHandler) ListAssets(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)

	sites, total, err := h.assets.ListSites(c.Request.Context(), projectID, c.Query("q"), page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	utils.SuccessWithPagination(c, gin.H{"items": sites, "q": c.Query("q")}, total, page, pageSize)
}

// CheckQuery 只校验查询串，不查库，供前端语法框实时反馈。
// GET /api/assets/query-check?q=...
func (h *AssetHandler) CheckQuery(c *gin.Context) {
	expr, _, err := repo.BuildAssetWhere(c.Query("q"))
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	utils.Success(c, gin.H{"valid": true, "compiled": expr})
}

// ListEvents 变更时间线。
// GET /api/events
func (h *AssetHandler) ListEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 || limit > 500 {
		limit = 50
	}
	rows, err := h.assets.RecentEvents(c.Request.Context(), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": rows, "limit": limit})
}

// ImportAssets 批量导入原始记录并归并（CSV 由调用方先解析成 JSON）。
// POST /api/assets/import
func (h *AssetHandler) ImportAssets(c *gin.Context) {
	var body struct {
		ProjectID int64            `json:"project_id" binding:"required"`
		Source    string           `json:"source"`
		Records   []repo.RawRecord `json:"records" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	if len(body.Records) == 0 || len(body.Records) > 5000 {
		utils.Error(c, utils.ErrCodeInvalidParams, "records 数量需在 1..5000")
		return
	}
	if body.Source == "" {
		body.Source = "api"
	}
	res, err := h.assets.ImportRecords(c.Request.Context(), body.ProjectID, body.Source, body.Records)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.SuccessWithMessage(c, fmt.Sprintf("导入 %d 条，新增站点 %d 个、入口 %d 个，重复 %d 条",
		res.Records, res.NewSites, res.NewEndpoints, res.DupRecords), res)
}

// VerifyAsset 手动触发一次可达性判定（P0 只落状态，不发网络请求）。
// POST /api/assets/:id/verify
func (h *AssetHandler) VerifyAsset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, "非法资产 ID")
		return
	}
	var body struct {
		Reachable  bool   `json:"reachable"`
		StatusCode int    `json:"status_code"`
		Reason     string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)
	if err := h.assets.VerifySite(c.Request.Context(), id, body.Reachable, body.StatusCode, body.Reason); err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"id": id, "reachable": body.Reachable})
}
