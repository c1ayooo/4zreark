package api

import (
	"strconv"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// SeedCollectionHandler 种子收集队列 + 巡航状态。
type SeedCollectionHandler struct{}

func NewSeedCollectionHandler() *SeedCollectionHandler { return &SeedCollectionHandler{} }

// Collect 批量入队种子收集（seed_ids 或 all=true 全选 live-capable 种子）
// @Router /api/projects/:id/seeds/collect [post]
func (h *SeedCollectionHandler) Collect(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	var req struct {
		SeedIDs []int64 `json:"seed_ids"`
		All     bool    `json:"all"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "请求体不合法")
		return
	}
	if !req.All && len(req.SeedIDs) == 0 {
		utils.BadRequest(c, "请选择要收集的种子（seed_ids 或 all）")
		return
	}
	enqueued, skipped, err := service.GetSeedCollectionService().Enqueue(c.Request.Context(), projectID, req.SeedIDs, req.All)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.SuccessWithMessage(c, "已入队", gin.H{"enqueued": enqueued, "skipped": skipped})
}

// Jobs 收集队列任务列表
// @Router /api/projects/:id/seeds/collect/jobs [get]
func (h *SeedCollectionHandler) Jobs(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	jobs, err := repo.Default().SeedCollection().ListJobs(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	active, _ := repo.Default().SeedCollection().CountActive(c.Request.Context(), projectID)
	utils.Success(c, gin.H{"items": jobs, "active": active})
}

// CruiseStatus 巡航状态（发现轮历史 + 站点巡检汇总）
// @Router /api/projects/:id/cruise/status [get]
func (h *SeedCollectionHandler) CruiseStatus(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	st, err := service.GetSeedCollectionService().GetCruiseStatus(c.Request.Context(), projectID)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, st)
}

// CruiseOverview 全部项目的巡航 v2 总览（自动巡航页顶部卡片）
// @Router /api/cruise/v2/overview [get]
func (h *SeedCollectionHandler) CruiseOverview(c *gin.Context) {
	rows, err := repo.Default().Pool().Query(c.Request.Context(), `
select p.id, p.name, p.code, p.collection_paused,
       (select ran_at from discovery_runs d where d.project_id = p.id order by ran_at desc limit 1),
       (select coalesce(sum(new_count),0) from discovery_runs d where d.project_id = p.id),
       (select count(*) from asset_candidates c where c.project_id = p.id and c.status = 'pending'),
       (select count(*) from sites s where s.project_id = p.id and s.state = 'reachable'),
       (select count(*) from sites s where s.project_id = p.id and s.content_checked_at >= now() - interval '24 hours'),
       (select count(*) from sites s where s.project_id = p.id and s.content_changed_at is not null),
       (select count(*) from seed_collection_jobs j where j.project_id = p.id and j.status in ('queued','running'))
from projects p order by p.id`)
	if err != nil {
		utils.InternalError(c, err.Error())
		return
	}
	defer rows.Close()
	type row struct {
		ProjectID    int64      `json:"project_id"`
		Name         string     `json:"name"`
		Code         string     `json:"code"`
		Paused       bool       `json:"paused"`
		LastRunAt    *time.Time `json:"last_run_at"`
		DiscoverNew  int64      `json:"discover_new"`
		Pending      int64      `json:"pending"`
		Reachable    int64      `json:"reachable"`
		Checked24h   int64      `json:"checked_24h"`
		ChangedTotal int64      `json:"changed_total"`
		Collecting   int64      `json:"collecting"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ProjectID, &r.Name, &r.Code, &r.Paused, &r.LastRunAt, &r.DiscoverNew,
			&r.Pending, &r.Reachable, &r.Checked24h, &r.ChangedTotal, &r.Collecting); err != nil {
			utils.InternalError(c, err.Error())
			return
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		// 游标中途出错不能把部分数据当完整结果返回
		utils.InternalError(c, err.Error())
		return
	}
	utils.Success(c, out)
}
