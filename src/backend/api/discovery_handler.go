package api

import (
	"strconv"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// DiscoveryHandler 资产巡航 v2：发现候选 + 站点内容巡检。
type DiscoveryHandler struct{}

func NewDiscoveryHandler() *DiscoveryHandler { return &DiscoveryHandler{} }

// ListCandidates 项目发现候选列表（status 默认 pending）
// @Router /api/projects/:id/candidates [get]
func (h *DiscoveryHandler) ListCandidates(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	status := c.DefaultQuery("status", "pending")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	items, err := repo.Default().AssetCandidates().ListCandidates(c.Request.Context(), projectID, status, limit)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	pending, _ := repo.Default().AssetCandidates().CountPending(c.Request.Context(), projectID)
	utils.Success(c, gin.H{"items": items, "pending": pending})
}

// DecideCandidates 批量接受/拒绝候选
// @Router /api/projects/:id/candidates/decide [post]
func (h *DiscoveryHandler) DecideCandidates(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	var req struct {
		IDs    []int64 `json:"ids" binding:"required"`
		Accept bool    `json:"accept"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法")
		return
	}
	updated, err := service.GetDiscoveryService().AcceptOrReject(c.Request.Context(), projectID, req.IDs, req.Accept)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已处理", gin.H{"updated": updated})
}

// RunDiscovery 手动触发一轮项目发现（不等每日周期）
// @Router /api/projects/:id/discovery/run [post]
func (h *DiscoveryHandler) RunDiscovery(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	summary, err := service.GetDiscoveryService().RunForProject(c.Request.Context(), projectID)
	if err != nil {
		_ = repo.Default().RecordDiscoveryRun(c.Request.Context(), projectID, 0, 0, 0, err.Error())
		utils.InternalError(c, "发现轮失败: "+err.Error())
		return
	}
	_ = repo.Default().RecordDiscoveryRun(c.Request.Context(), projectID,
		summary.FromCTLog, summary.FromEngines, int(summary.NewCount), "")
	utils.SuccessWithMessage(c, "发现轮完成", summary)
}

// SetWatchExcluded 站点巡检豁免开关
// @Router /api/sites/:id/watch-excluded [put]
func (h *DiscoveryHandler) SetWatchExcluded(c *gin.Context) {
	siteID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || siteID <= 0 {
		utils.BadRequest(c, "站点 ID 不合法")
		return
	}
	var req struct {
		Excluded bool `json:"excluded"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法")
		return
	}
	if err := repo.NewAssetRepo().SetSiteWatchExcluded(c.Request.Context(), siteID, req.Excluded); err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已保存", gin.H{"excluded": req.Excluded})
}

// WatchStatus 单站巡检状态
// @Router /api/sites/:id/watch-status [get]
func (h *DiscoveryHandler) WatchStatus(c *gin.Context) {
	siteID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || siteID <= 0 {
		utils.BadRequest(c, "站点 ID 不合法")
		return
	}
	var row struct {
		ContentHash   string     `json:"content_hash"`
		TextHash      string     `json:"content_text_hash"`
		CheckedAt     *time.Time `json:"content_checked_at"`
		ChangedAt     *time.Time `json:"content_changed_at"`
		WatchExcluded bool       `json:"watch_excluded"`
	}
	err = repo.Default().Pool().QueryRow(c.Request.Context(), `
select coalesce(content_hash,''), coalesce(content_text_hash,''),
       content_checked_at, content_changed_at, watch_excluded
from sites where id = $1`, siteID).Scan(
		&row.ContentHash, &row.TextHash, &row.CheckedAt, &row.ChangedAt, &row.WatchExcluded)
	if err != nil {
		utils.NotFound(c, "站点不存在")
		return
	}
	utils.Success(c, row)
}
