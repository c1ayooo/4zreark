package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// DashboardHandler 仪表盘统计入口。
// 统计全部走 PG（repo.DashboardRepo），不再依赖已移除的 Mongo service。
type DashboardHandler struct {
	dashboard *repo.DashboardRepo
}

func NewDashboardHandler() *DashboardHandler {
	return &DashboardHandler{dashboard: repo.NewDashboardRepo()}
}

// GetDashboardStats returns dashboard statistics
// GET /api/dashboard/stats
func (h *DashboardHandler) GetDashboardStats(c *gin.Context) {
	stats, err := h.dashboard.Stats(c.Request.Context())
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, stats)
}

// GetRecentTasks returns recent tasks
// GET /api/dashboard/recent-tasks
func (h *DashboardHandler) GetRecentTasks(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := h.dashboard.RecentTasks(c.Request.Context(), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, rows)
}

// GetRecentVulnerabilities returns recent vulnerabilities
// GET /api/dashboard/recent-vulns
func (h *DashboardHandler) GetRecentVulnerabilities(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := h.dashboard.RecentVulns(c.Request.Context(), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, rows)
}

// GetRecentAssets 返回最近发现的站点（新资产域）。
// GET /api/dashboard/recent-assets
func (h *DashboardHandler) GetRecentAssets(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := h.dashboard.RecentAssets(c.Request.Context(), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, rows)
}

// GetTrends returns trend data for the dashboard
// GET /api/dashboard/trends?days=7
func (h *DashboardHandler) GetTrends(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days <= 0 {
		days = 7
	}
	if days > 30 {
		days = 30
	}
	trends, err := h.dashboard.Trends(c.Request.Context(), days)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, trends)
}

// GetRecentActivities returns recent activities
// GET /api/dashboard/activities?limit=5
func (h *DashboardHandler) GetRecentActivities(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	rows, err := h.dashboard.Activities(c.Request.Context(), limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	utils.Success(c, rows)
}
