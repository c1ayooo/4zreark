package api

import (
	"errors"
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// AssetHandler 是资产治理域（读侧 + 导入）的 HTTP 入口。
// 只做参数绑定与错误映射，业务逻辑在 service.AssetService。
type AssetHandler struct {
	assets *service.AssetService
}

func NewAssetHandler() *AssetHandler {
	return &AssetHandler{assets: service.NewAssetService()}
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

// ListAssets 资产列表：view × kind × catalog 三层维度 + DSL。
// GET /api/assets?kind=site&catalog=verified&view=lost&site_group=1&page=1&page_size=20&q=...
//
// 容错口径（v4 §11.4）：q 语法错误明确报错；kind/catalog/view 非法值静默回落缺省。
func (h *AssetHandler) ListAssets(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	siteGroup := c.DefaultQuery("site_group", "1") != "0"

	res, err := h.assets.ListAssets(c.Request.Context(), repo.AssetQuery{
		ProjectID: projectID,
		Q:         c.Query("q"),
		Kind:      c.Query("kind"),
		Catalog:   c.Query("catalog"),
		View:      c.Query("view"),
		SiteGroup: siteGroup,
		Page:      page,
		PageSize:  pageSize,
	})
	if err != nil {
		if errors.Is(err, repo.ErrDSLSyntax) {
			utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, res)
}

// CheckQuery 只校验查询串，不查库，供前端语法框实时反馈。
// GET /api/assets/query-check?q=...
func (h *AssetHandler) CheckQuery(c *gin.Context) {
	compiled, err := h.assets.CheckQuery(c.Query("q"))
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	utils.Success(c, gin.H{"valid": true, "compiled": compiled})
}

// ListEvents 变更时间线。
// GET /api/events
func (h *AssetHandler) ListEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
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

	res, err := h.assets.ImportRecords(c.Request.Context(), body.ProjectID, body.Source, body.Records)
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	utils.SuccessWithMessage(c, importMessage(res), res)
}

func importMessage(res *repo.ImportResult) string {
	return "导入 " + strconv.Itoa(res.Records) + " 条，新增站点 " + strconv.Itoa(res.NewSites) +
		" 个、入口 " + strconv.Itoa(res.NewEndpoints) + " 个，重复 " + strconv.Itoa(res.DupRecords) + " 条"
}

// VerifyAsset 人工判定一次可达性（不发网络请求，仅供人工修正）。
// 真实探测在 POST /api/assets/:id/probe。
// POST /api/assets/:id/verify
func (h *AssetHandler) VerifyAsset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法资产 ID")
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
