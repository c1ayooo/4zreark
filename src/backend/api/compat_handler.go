package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// CompatHandler 提供 ScopesHub 端点表里的兼容入口。
// 这些路径不新增业务逻辑，只是把已有能力按对方契约暴露，减少前端联调时的分支。
type CompatHandler struct {
	assets *service.AssetService
}

func NewCompatHandler() *CompatHandler {
	return &CompatHandler{assets: service.NewAssetService()}
}

// Changes 变更时间线（按项目/事件类型过滤）。
// GET /api/changes?project_id=&event_type=&limit=
func (h *CompatHandler) Changes(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	items, err := h.assets.ListEventsFiltered(c.Request.Context(), projectID, c.Query("event_type"), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": items, "total": len(items), "limit": limit})
}

// RecentAssets 最近发现的资产（按 first_seen 倒序，缺省 10 条）。
// GET /api/dashboard/recent-assets?project_id=&limit=
func (h *CompatHandler) RecentAssets(c *gin.Context) {
	projectID, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	page, err := h.assets.ListAssets(c.Request.Context(), repo.AssetQuery{
		ProjectID: projectID, Page: 1, PageSize: limit,
	})
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, gin.H{"items": page.Items, "total": page.Total, "limit": limit})
}
