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

// GetProject 项目详情。GET /api/projects/:id
func (h *AssetHandler) GetProject(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	p, err := h.assets.GetProject(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "项目不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, p)
}

type projectBody struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Region      string `json:"region"`
	Description string `json:"description"`
	HomepageURL string `json:"homepage_url"`
	Color       string `json:"color"`
	CycleDays   int    `json:"cycle_interval_days"`
}

func (b projectBody) input() repo.ProjectInput {
	return repo.ProjectInput{
		Code:        b.Code,
		Name:        b.Name,
		Region:      b.Region,
		Description: b.Description,
		HomepageURL: b.HomepageURL,
		Color:       b.Color,
		CycleDays:   b.CycleDays,
	}
}

// CreateProject 新建项目。POST /api/projects
func (h *AssetHandler) CreateProject(c *gin.Context) {
	var body projectBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	p, err := h.assets.CreateProject(c.Request.Context(), body.input())
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "项目已创建", p)
}

// UpdateProject 编辑项目资料。PUT /api/projects/:id
func (h *AssetHandler) UpdateProject(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	var body projectBody
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	p, err := h.assets.UpdateProject(c.Request.Context(), id, body.input())
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "项目不存在")
			return
		}
		utils.BadRequest(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "项目已更新", p)
}

// SetProjectPaused 暂停/恢复采集。POST /api/projects/:id/pause|resume
func (h *AssetHandler) SetProjectPaused(c *gin.Context, paused bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法项目 ID")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)
	p, err := h.assets.SetProjectPaused(c.Request.Context(), id, paused, body.Reason)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "项目不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	msg := "已恢复采集"
	if paused {
		msg = "已暂停采集"
	}
	utils.SuccessWithMessage(c, msg, p)
}

func (h *AssetHandler) PauseProject(c *gin.Context)  { h.SetProjectPaused(c, true) }
func (h *AssetHandler) ResumeProject(c *gin.Context) { h.SetProjectPaused(c, false) }

// ListAssets 资产列表：view × kind × catalog 三层维度 + DSL。
// GET /api/assets?kind=site&catalog=verified&view=lost&site_group=1&sort=risk&page=1&page_size=20&q=...
//
// 容错口径（v4 §11.4）：q 语法错误明确报错；kind/catalog/view/sort 非法值静默回落缺省。
func (h *AssetHandler) ListAssets(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	siteGroup := c.DefaultQuery("site_group", "1") != "0"
	cursor, hasCursor := c.GetQuery("cursor")

	res, err := h.assets.ListAssets(c.Request.Context(), repo.AssetQuery{
		ProjectID: projectID,
		Q:         c.Query("q"),
		Kind:      c.Query("kind"),
		Catalog:   c.Query("catalog"),
		View:      c.Query("view"),
		SiteGroup: siteGroup,
		Sort:      c.Query("sort"),
		Page:      page,
		PageSize:  pageSize,
		UseCursor: hasCursor,
		Cursor:    cursor,
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

// ListTaskAssets 任务详情「本任务资产」：该任务贡献过证据的归并站点。
// GET /api/tasks/:id/assets?page=1&page_size=20&q=
func (h *AssetHandler) ListTaskAssets(c *gin.Context) {
	taskID := c.Param("id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	items, total, err := h.assets.ListTaskSites(c.Request.Context(), taskID, page, pageSize, c.Query("q"))
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"list": items, "total": total, "page": page, "pageSize": pageSize})
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

// GetAsset 资产详情：站点、入口、验证历史、指纹命中、原始记录、事件与关系证据。
// GET /api/assets/:id
func (h *AssetHandler) GetAsset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	detail, err := h.assets.GetAssetDetail(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "资产不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, detail)
}

// ListSiteRecords 站点原始记录分页：GET /api/assets/:id/records?cursor=&limit=50
func (h *AssetHandler) ListSiteRecords(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	items, next, more, err := h.assets.ListSiteRecords(c.Request.Context(), id, c.Query("cursor"), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "next_cursor": next, "has_more": more})
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

	res, err := h.assets.Ingest(c.Request.Context(), body.ProjectID, body.Source, body.Records)
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

// PreviewImport 两段式导入第一步：只校验/去重/抽样，不写库。
// POST /api/assets/import/preview
func (h *AssetHandler) PreviewImport(c *gin.Context) {
	var body struct {
		ProjectID int64            `json:"project_id" binding:"required"`
		Source    string           `json:"source"`
		Records   []repo.RawRecord `json:"records" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	preview, err := h.assets.PreviewImport(c.Request.Context(), body.ProjectID, body.Source, body.Records)
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "预览已生成，15 分钟内有效", preview)
}

// CommitImport 两段式导入第二步：消费预览 token 并真正入库。
// POST /api/assets/import/commit
func (h *AssetHandler) CommitImport(c *gin.Context) {
	var body struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, "缺少预览 token")
		return
	}
	res, err := h.assets.CommitImport(c.Request.Context(), body.Token)
	if err != nil {
		if errors.Is(err, service.ErrImportPreviewExpired) {
			utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		return
	}
	utils.SuccessWithMessage(c, importMessage(res), res)
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

// IconClusters 按图标聚类。GET /api/assets/icons?project_id=&q=&page=&page_size=
func (h *AssetHandler) IconClusters(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "60"))

	items, total, err := h.assets.IconClusters(c.Request.Context(), projectID, c.Query("q"), page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize,
		"view": "icons", "view_supported": true})
}

// TechClusters 按技术栈聚类。GET /api/assets/technologies?project_id=&q=&page=&page_size=
func (h *AssetHandler) TechClusters(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "60"))

	items, total, err := h.assets.TechClusters(c.Request.Context(), projectID, c.Query("q"), page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize,
		"view": "technologies", "view_supported": true})
}

// IconImage 输出图标字节。GET /api/asset-icons/:sha256
// 放在公开组：图标本身就是公开站点的 favicon，且 <img> 标签带不了 Authorization。
func (h *AssetHandler) IconImage(c *gin.Context) {
	sha := c.Param("sha256")
	data, ctype, err := h.assets.IconBytes(c.Request.Context(), sha)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			c.Status(404)
			return
		}
		c.Status(500)
		return
	}
	if ctype == "" {
		ctype = "image/x-icon"
	}
	// 内容按 sha256 寻址，永不变化，可以长缓存
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Data(200, ctype, data)
}

// AssetGraph 资产星图（分层图数据）。
// GET /api/assets/graph?project_id=&q=
//
// 与 /api/assets 的区别：不分页、保留父子关系，供前端做分层布局。
func (h *AssetHandler) AssetGraph(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	query := repo.AssetQuery{
		ProjectID: projectID,
		Q:         c.Query("q"),
	}
	var (
		g   *repo.AssetGraphData
		err error
	)
	if c.Query("mode") == "summary" {
		g, err = h.assets.AssetGraphSummary(c.Request.Context(), query)
	} else {
		g, err = h.assets.AssetGraph(c.Request.Context(), query)
	}
	if err != nil {
		if errors.Is(err, repo.ErrDSLSyntax) {
			utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, g)
}

// ListSiteRoutes 某站点已采集的路由（path 粒度）。
// GET /api/assets/routes?site_id=123&limit=200
func (h *AssetHandler) ListSiteRoutes(c *gin.Context) {
	siteID, _ := strconv.ParseInt(c.Query("site_id"), 10, 64)
	if siteID <= 0 {
		utils.BadRequest(c, "需要 site_id")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	routes, err := h.assets.ListSiteRoutes(siteID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, routes)
}
