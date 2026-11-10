package api

import (
	"encoding/csv"
	"errors"
	"strconv"
	"strings"
	"time"

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
//	&with_recent=1&recent_limit=5  站点列表顺带返回每站最近几条采集证据
//
// 容错口径（v4 §11.4）：q 语法错误明确报错；kind/catalog/view/sort 非法值静默回落缺省。
// ExportAssets 服务端 CSV 导出（GET /api/assets/export）。
// 复用列表筛选参数，分页遍历站点行（平铺不分组），上限 10 万行；公式注入
// 在服务端做一次统一消毒（前端导出同样处理，双保险）。
// @Router /api/assets/export [get]
func (h *AssetHandler) ExportAssets(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	csvFile := "assets-" + time.Now().Format("20060102-150405") + ".csv"
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+csvFile+`"`)

	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"id", "host", "ip", "protocol", "port", "url", "title", "status", "state",
		"risk_score", "tags", "technology_stack", "cert_not_after", "first_seen", "last_seen", "project"})

	const pageSize = 500
	const maxRows = 100000
	written := 0
	for page := 1; written < maxRows; page++ {
		res, err := h.assets.ListAssets(c.Request.Context(), repo.AssetQuery{
			ProjectID: projectID,
			Q:         c.Query("q"),
			Starred:   starredParam(c.Query("starred")),
			Tag:       c.Query("tag"),
			SiteGroup: false, // 平铺站点行，行元素是 *Site
			Page:      page,
			PageSize:  pageSize,
		})
		if err != nil {
			return // 头已发出，中断流即可
		}
		items, _ := res.Items.([]*repo.Site)
		if len(items) == 0 {
			break
		}
		for _, st := range items {
			if written >= maxRows {
				break
			}
			written++
			_ = w.Write([]string{
				strconv.FormatInt(st.ID, 10),
				sanitizeCSVCell(st.Host), sanitizeCSVCell(st.IP),
				st.Protocol, strconv.Itoa(st.Port),
				sanitizeCSVCell(st.Value), sanitizeCSVCell(st.Title),
				strconv.Itoa(st.HTTPStatus), st.State,
				strconv.Itoa(st.RiskScore),
				sanitizeCSVCell(strings.Join(st.Tags, "|")),
				sanitizeCSVCell(strings.Join(st.Tech, "|")),
				csvTimePtr(st.CertNotAfter), csvTime(st.FirstSeen), csvTime(st.LastSeen),
				sanitizeCSVCell(st.ProjectName),
			})
		}
		if res.Total > 0 && int64(page*pageSize) >= res.Total {
			break
		}
	}
	w.Flush()
}

// sanitizeCSVCell 防 CSV 公式注入：以 = + - @ 开头的单元格前置单引号。
func sanitizeCSVCell(v string) string {
	if len(v) > 0 && (v[0] == '=' || v[0] == '+' || v[0] == '-' || v[0] == '@') {
		return "'" + v
	}
	return v
}

func csvTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func csvTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return csvTime(*t)
}

func (h *AssetHandler) ListAssets(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	siteGroup := c.DefaultQuery("site_group", "1") != "0"
	cursor, hasCursor := c.GetQuery("cursor")
	recentLimit, _ := strconv.Atoi(c.DefaultQuery("recent_limit", "5"))

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
		// 行内最近记录是可选开销：默认不查，前端展开某一行时才带 with_recent=1。
		WithRecentRecords:  c.Query("with_recent") == "1" || c.Query("with_recent") == "true",
		RecentRecordsLimit: recentLimit,
		Starred:            starredParam(c.Query("starred")),
		Tag:                c.Query("tag"),
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

// starredParam 解析「只看星标」开关：1/true → true，0/false → false，空 → 不过滤。
func starredParam(v string) *bool {
	if v == "" {
		return nil
	}
	t := v == "1" || v == "true"
	return &t
}

// UpdateAssetGovernance 资产治理操作：星标 / 标签 / 备注。
// POST /api/assets/:id/governance {"starred":true,"tags":["重点"],"note":"..."}
// 三个字段全部可选，传了才改（部分更新）。
func (h *AssetHandler) UpdateAssetGovernance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	var body struct {
		Starred *bool     `json:"starred"`
		Tags    *[]string `json:"tags"`
		Note    *string   `json:"note"`
		Ignored *bool     `json:"ignored"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequest(c, "请求体格式错误")
		return
	}
	if err := h.assets.UpdateSiteGovernance(c.Request.Context(), id, repo.SiteGovernanceInput{
		Starred: body.Starred,
		Tags:    body.Tags,
		Note:    body.Note,
		Ignored: body.Ignored,
	}); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			utils.NotFound(c, "资产不存在")
			return
		}
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"ok": true})
}

// DeleteAsset 永久删除单个资产（排除非归属资产用，不限 lost 状态）。
// DELETE /api/assets/:id
// 级联清单与失联删除一致；保护期内拒绝，文案带到期时间。
func (h *AssetHandler) DeleteAsset(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	actor, _ := c.Get("username")
	name, _ := actor.(string)
	if err := h.assets.DeleteAsset(c.Request.Context(), id, name, c.ClientIP()); err != nil {
		switch {
		case errors.Is(err, repo.ErrNotFound):
			utils.NotFound(c, "资产不存在")
		case errors.Is(err, service.ErrAssetProtected):
			utils.Error(c, utils.ErrCodeInvalidParams, err.Error())
		default:
			utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		}
		return
	}
	utils.SuccessWithMessage(c, "已删除", gin.H{"id": id})
}

// ListFingerprintScores 指纹评分列表：项目内资产按指纹命中算 0-100 分。
// GET /api/assets/fingerprint-scores?project_id=1&min_score=40&max_score=100&level=high
//
//	&category=OA&fingerprint=Jenkins&q=example.com&sort=score&page=1&page_size=20
func (h *AssetHandler) ListFingerprintScores(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	minScore, _ := strconv.Atoi(c.Query("min_score"))
	maxScore, _ := strconv.Atoi(c.Query("max_score"))

	res, err := h.assets.ListFingerprintScores(c.Request.Context(), repo.FpScoreQuery{
		ProjectID:   projectID,
		Category:    c.Query("category"),
		Fingerprint: c.Query("fingerprint"),
		Level:       c.Query("level"),
		MinScore:    minScore,
		MaxScore:    maxScore,
		Q:           c.Query("q"),
		Sort:        c.Query("sort"),
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
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

// ListSiteRecords 站点原始记录分页：GET /api/assets/:id/records?cursor=&limit=50&interface=1&crawler=1
// interface=1 只返回接口候选（方法/JSON/jsluice/查询串/路径段判定，不要求 /api 前缀）。
// crawler=1 只返回爬虫发现的记录（katana 采集，或历史记录里带 tag/attribute/referrer 的）。
func (h *AssetHandler) ListSiteRecords(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		utils.BadRequest(c, "非法资产 ID")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	interfaceOnly := c.Query("interface") == "1" || c.Query("interface") == "true"
	crawlerOnly := c.Query("crawler") == "1" || c.Query("crawler") == "true"
	items, next, more, err := h.assets.ListSiteRecords(c.Request.Context(), id, c.Query("cursor"), limit, interfaceOnly, crawlerOnly)
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
	msg := "导入 " + strconv.Itoa(res.Records) + " 条，新增站点 " + strconv.Itoa(res.NewSites) +
		" 个、入口 " + strconv.Itoa(res.NewEndpoints) + " 个，重复 " + strconv.Itoa(res.DupRecords) + " 条"
	// 命中数写进返回文案：指纹识别到了却没落库，用户此前只能在库里翻表才能发现。
	if res.FingerprintHits > 0 {
		msg += "，指纹命中 " + strconv.Itoa(res.FingerprintHits) + " 条"
	}
	if res.UnmatchedRules > 0 {
		msg += "，" + strconv.Itoa(res.UnmatchedRules) + " 个指纹名未收录规则库"
	}
	return msg
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

// AppOptions 「按指纹筛选」下拉候选。GET /api/assets/apps?q=&limit=
func (h *AssetHandler) AppOptions(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	items, err := h.assets.AppOptions(c.Request.Context(), c.Query("q"), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items})
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
