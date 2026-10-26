package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// 采集完成综合评估：聚合项目资产面（企业实体/数字资产名单/域名候选/种子/站点）
// 与风险面（注销主体、无备案域名、group 待确认、非常规端口、明文 HTTP、失效会话），
// 组装成通知消息。触发点：BFS 深度采集完成、手动数字资产采集、巡航采集收尾。

// CollectionAssessment 一次采集完成后的综合评估。
type CollectionAssessment struct {
	ProjectID   int64  `json:"project_id"`
	ProjectName string `json:"project_name"`
	Trigger     string `json:"trigger"`

	// 资产面
	Entities          int            `json:"entities"`
	EntitiesDead      int            `json:"entities_dead"`
	DigitalAssets     int            `json:"digital_assets"`
	DigitalByKind     map[string]int `json:"digital_by_kind"`
	DigitalPending    int            `json:"digital_pending"`
	DomainCandidates  int            `json:"domain_candidates"`
	DomainNoICP       int            `json:"domain_no_icp"`
	DomainGroupPend   int            `json:"domain_group_pending"`
	Seeds             int            `json:"seeds"`
	Sites             int            `json:"sites"`
	SitesOddPort      int            `json:"sites_odd_port"`
	SitesPlainHTTP    int            `json:"sites_plain_http"`
	SitesCertExpiring int            `json:"sites_cert_expiring"`
	ExpiredSessions   int            `json:"expired_sessions"`

	// 风险与结论
	Risks   []string `json:"risks"`
	Summary string   `json:"summary"`
}

// assessmentThrottle 同项目评估通知的最小间隔（BFS 完成钩子可能短时间连发）。
var (
	assessmentMu       sync.Mutex
	assessmentLastSent = map[int64]time.Time{}
)

const assessmentThrottleInterval = 10 * time.Minute

// BuildCollectionAssessment 从库内聚合项目的资产面与风险面。
func BuildCollectionAssessment(ctx context.Context, projectID int64, trigger string) (*CollectionAssessment, error) {
	r := repo.Default()
	if r == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	a := &CollectionAssessment{ProjectID: projectID, Trigger: trigger, DigitalByKind: map[string]int{}}

	var projectName string
	if err := r.Pool().QueryRow(ctx,
		`select name from projects where id = $1`, projectID).Scan(&projectName); err != nil {
		return nil, fmt.Errorf("读取项目失败: %w", err)
	}
	a.ProjectName = projectName

	// 企业实体（含注销/吊销仍在列的）
	if err := r.Pool().QueryRow(ctx, `
select count(*), count(*) filter (where open_status ~ '注销|吊销|迁出')
  from enterprise_entities where project_id = $1`, projectID).Scan(&a.Entities, &a.EntitiesDead); err != nil {
		return nil, err
	}

	// 数字资产名单（按类型）+ 待确认候选
	kindRows, err := r.Pool().Query(ctx, `
select kind, count(*) from digital_assets where project_id = $1 group by kind`, projectID)
	if err != nil {
		return nil, err
	}
	for kindRows.Next() {
		var k string
		var n int
		if err := kindRows.Scan(&k, &n); err != nil {
			kindRows.Close()
			return nil, err
		}
		a.DigitalByKind[k] = n
		a.DigitalAssets += n
	}
	kindRows.Close()
	if err := r.Pool().QueryRow(ctx, `
select count(*) from digital_candidates where project_id = $1 and status = 'candidate'`,
		projectID).Scan(&a.DigitalPending); err != nil {
		return nil, err
	}

	// 域名候选（含无备案、group 待确认）
	if err := r.Pool().QueryRow(ctx, `
select count(*),
       count(*) filter (where coalesce(icp,'') = ''),
       count(*) filter (where coalesce(icp,'') = '' and entity_name in (
           select name from enterprise_entities
            where project_id = $1 and entity_type = 'group'))
  from enterprise_candidates where project_id = $1 and status = 'candidate'`,
		projectID).Scan(&a.DomainCandidates, &a.DomainNoICP, &a.DomainGroupPend); err != nil {
		return nil, err
	}

	// 种子 / 站点资产 / 风险面
	if err := r.Pool().QueryRow(ctx, `
select count(*) from seeds where project_id = $1 and enabled`, projectID).Scan(&a.Seeds); err != nil {
		return nil, err
	}
	if err := r.Pool().QueryRow(ctx, `
select count(*),
       count(*) filter (where port not in (80, 443)),
       count(*) filter (where protocol = 'http'),
       count(*) filter (where cert_not_after is not null and cert_not_after < now() + interval '30 days')
  from sites where project_id = $1`,
		projectID).Scan(&a.Sites, &a.SitesOddPort, &a.SitesPlainHTTP, &a.SitesCertExpiring); err != nil {
		return nil, err
	}
	if err := r.Pool().QueryRow(ctx, `
select count(*) from datasource_sessions where status = 'expired'`).Scan(&a.ExpiredSessions); err != nil {
		return nil, err
	}

	// 风险清单
	if a.EntitiesDead > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 家主体已注销/吊销仍在实体列表，建议剔除", a.EntitiesDead))
	}
	if a.DigitalPending > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 条数字资产候选待确认（确认后才入名单）", a.DigitalPending))
	}
	if a.DomainNoICP > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 个域名候选无备案归属信息，建议人工确认后再转种子", a.DomainNoICP))
	}
	if a.DomainGroupPend > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 个集团成员域名待人工确认（group 口径不自动归属）", a.DomainGroupPend))
	}
	if a.SitesOddPort > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 个站点暴露在非常规端口（非 80/443）", a.SitesOddPort))
	}
	if a.SitesPlainHTTP > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 个站点为明文 HTTP", a.SitesPlainHTTP))
	}
	if a.SitesCertExpiring > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 个站点证书 30 天内到期或已过期", a.SitesCertExpiring))
	}
	if a.ExpiredSessions > 0 {
		a.Risks = append(a.Risks, fmt.Sprintf("%d 个数据源会话已失效，相关采集将中断", a.ExpiredSessions))
	}

	a.Summary = fmt.Sprintf("覆盖 %d 家主体、%d 条数字资产（APP %d / 小程序 %d / 公众号 %d / 新媒体 %d）、%d 个域名候选、%d 个种子、%d 个站点；风险 %d 项。",
		a.Entities, a.DigitalAssets,
		a.DigitalByKind["app"], a.DigitalByKind["miniapp"],
		a.DigitalByKind["official_account"], a.DigitalByKind["newmedia"],
		a.DomainCandidates, a.Seeds, a.Sites, len(a.Risks))

	// 快照落表（尽力而为；趋势查询的数据源）
	if statsB, merr := json.Marshal(a); merr == nil {
		_, _ = r.Pool().Exec(ctx, `
insert into collection_assessment_snapshots (project_id, stats) values ($1, $2::jsonb)`,
			projectID, string(statsB))
	}
	return a, nil
}

// AssessmentTrendPoint 趋势数据点。
type AssessmentTrendPoint struct {
	TakenAt time.Time       `json:"taken_at"`
	Stats   json.RawMessage `json:"stats"`
}

// ProjectAssessmentTrend 最近一次评估 + 历史趋势（最多 limit 个点，时间升序）。
func ProjectAssessmentTrend(ctx context.Context, projectID int64, limit int) (*CollectionAssessment, []AssessmentTrendPoint, error) {
	r := repo.Default()
	if r == nil {
		return nil, nil, fmt.Errorf("数据层未初始化")
	}
	if limit <= 0 || limit > 90 {
		limit = 30
	}
	var latestStats []byte
	var latest CollectionAssessment
	row := r.Pool().QueryRow(ctx, `
select stats from collection_assessment_snapshots
 where project_id = $1 order by taken_at desc, id desc limit 1`, projectID)
	if err := row.Scan(&latestStats); err != nil {
		return nil, nil, nil // 从未有评估
	}
	if err := json.Unmarshal(latestStats, &latest); err != nil {
		return nil, nil, fmt.Errorf("解析最近评估失败: %w", err)
	}
	latest.ProjectName, _ = func() (string, error) {
		var n string
		err := r.Pool().QueryRow(ctx, `select name from projects where id=$1`, projectID).Scan(&n)
		return n, err
	}()

	rows, err := r.Pool().Query(ctx, `
select taken_at, stats from collection_assessment_snapshots
 where project_id = $1 order by taken_at desc, id desc limit $2`, projectID, limit)
	if err != nil {
		return &latest, nil, err
	}
	defer rows.Close()
	trend := []AssessmentTrendPoint{}
	for rows.Next() {
		var p AssessmentTrendPoint
		if err := rows.Scan(&p.TakenAt, &p.Stats); err != nil {
			return &latest, nil, err
		}
		trend = append(trend, p)
	}
	// 时间升序返回
	for i, j := 0, len(trend)-1; i < j; i, j = i+1, j-1 {
		trend[i], trend[j] = trend[j], trend[i]
	}
	return &latest, trend, nil
}

// SendCollectionAssessmentAsync 组装并异步发送评估通知；respectThrottle=true 时
// 同项目 10 分钟内只发一次（BFS 完成钩子防刷屏）。无通知渠道时静默。
func SendCollectionAssessmentAsync(projectID int64, trigger string, respectThrottle bool) {
	if respectThrottle {
		assessmentMu.Lock()
		if last, ok := assessmentLastSent[projectID]; ok && time.Since(last) < assessmentThrottleInterval {
			assessmentMu.Unlock()
			return
		}
		assessmentLastSent[projectID] = time.Now()
		assessmentMu.Unlock()
	}
	go func() {
		defer func() { _ = recover() }()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		a, err := BuildCollectionAssessment(ctx, projectID, trigger)
		if err != nil {
			return
		}
		level := notify.NotifyLevelInfo
		if len(a.Risks) > 0 {
			level = notify.NotifyLevelWarning
		}
		content := fmt.Sprintf("触发：%s\n%s", a.Trigger, a.Summary)
		if len(a.Risks) > 0 {
			content += "\n风险提示：\n- " + strings.Join(a.Risks, "\n- ")
		}
		notify.GetGlobalManager().SendAsync(&notify.NotifyMessage{
			Level:     level,
			Title:     "采集完成综合评估 · " + a.ProjectName,
			Content:   content,
			Timestamp: time.Now(),
			Source:    "collection-assessment",
			Extra: map[string]interface{}{
				"project_id": projectID, "risks": len(a.Risks), "sites": a.Sites,
			},
		})
	}()
}
