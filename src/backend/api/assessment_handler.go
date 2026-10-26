package api

import (
	"strconv"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

// AssessmentHandler 采集完成综合评估：最近评估 + 资产面趋势（快照）。
type AssessmentHandler struct{}

func NewAssessmentHandler() *AssessmentHandler { return &AssessmentHandler{} }

// GetProjectAssessment GET /api/projects/:id/assessment
func (h *AssessmentHandler) GetProjectAssessment(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("trend_limit", "30"))
	latest, trend, err := service.ProjectAssessmentTrend(c.Request.Context(), projectID, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	if latest == nil {
		utils.NotFound(c, "该项目还没有评估快照（完成一次采集后生成）")
		return
	}
	utils.Success(c, gin.H{"latest": latest, "trend": trend})
}


// ListAssessmentSites GET /api/projects/:id/assessment/sites?filter=
// 评估风险下钻：plain_http=明文 HTTP 站点、odd_port=非常规端口站点、cert_expiring=证书 30 天内到期。
func (h *AssessmentHandler) ListAssessmentSites(c *gin.Context) {
	projectID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || projectID <= 0 {
		utils.BadRequest(c, "项目 ID 不合法")
		return
	}
	filter := c.DefaultQuery("filter", "plain_http")
	var cond string
	switch filter {
	case "plain_http":
		cond = "protocol = 'http'"
	case "odd_port":
		cond = "port not in (80, 443)"
	case "cert_expiring":
		cond = "cert_not_after is not null and cert_not_after < now() + interval '30 days'"
	default:
		utils.BadRequest(c, "filter 只支持 plain_http / odd_port / cert_expiring")
		return
	}
	r := repo.Default()
	if r == nil {
		utils.Error(c, utils.ErrCodeDatabaseError, "数据层未初始化")
		return
	}
	rows, err := r.Pool().Query(c.Request.Context(), `
select id, host, port, protocol, coalesce(http_status, 0), coalesce(title, '')
  from sites where project_id = $1 and `+cond+` order by host limit 200`, projectID)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	defer rows.Close()
	type siteRow struct {
		ID         int64  `json:"id"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		Protocol   string `json:"protocol"`
		HTTPStatus int    `json:"http_status"`
		Title      string `json:"title"`
	}
	items := []siteRow{}
	for rows.Next() {
		var sr siteRow
		if err := rows.Scan(&sr.ID, &sr.Host, &sr.Port, &sr.Protocol, &sr.HTTPStatus, &sr.Title); err != nil {
			utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
			return
		}
		items = append(items, sr)
	}
	utils.Success(c, gin.H{"items": items, "total": len(items)})
}
