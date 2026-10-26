package repo

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// 资产事件（G5）：first_seen / attribute_change / reappear。
// 事件只记录真实变化，不记录每次探测流水；探测流水仍在 verifications。

// OnSiteDown 站点判死回调：VerifySite 状态翻转为 lost 后触发（提交成功才调）。
// repo 不能反向依赖 service/notify，由 main 在 master 启动时注入通知钩子；
// worker 不安装、不发通知。nil = 无订阅方。
var OnSiteDown func(projectID, siteID int64, value, reason string)

type SiteSnapshot struct {
	ProjectID  int64
	State      string
	Title      string
	HTTPStatus int
	Tech       []string
	IconSHA256 string
	IP         string
}

// SiteSnapshot 读取站点当前快照（探测前后对比用）。
func (a *AssetRepo) SiteSnapshot(ctx context.Context, siteID int64) (*SiteSnapshot, error) {
	var s SiteSnapshot
	var tech []byte
	err := a.r.pool.QueryRow(ctx, `
SELECT project_id, state, coalesce(title, ''), http_status, tech,
       coalesce(icon_sha256, ''), coalesce(ip::text, '')
  FROM sites WHERE id = $1`, siteID).
		Scan(&s.ProjectID, &s.State, &s.Title, &s.HTTPStatus, &tech, &s.IconSHA256, &s.IP)
	if err != nil {
		return nil, err
	}
	if len(tech) > 0 {
		_ = json.Unmarshal(tech, &s.Tech)
	}
	return &s, nil
}

// InsertEvent 写入一条资产事件。recordID 可为 nil（探测事件没有原始记录）。
func (a *AssetRepo) InsertEvent(ctx context.Context, projectID, siteID int64, recordID *int64, eventType, title string, before, after map[string]any) error {
	_, err := a.r.pool.Exec(ctx, `
INSERT INTO asset_events (project_id, site_id, record_id, event_type, title, before, after)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		projectID, siteID, recordID, eventType, title, toJSONB(before), toJSONB(after))
	return err
}

// insertEventTx 导入事务内写事件。
func insertEventTx(ctx context.Context, tx pgx.Tx, projectID, siteID int64, recordID *int64, eventType, title string, before, after map[string]any) error {
	_, err := tx.Exec(ctx, `
INSERT INTO asset_events (project_id, site_id, record_id, event_type, title, before, after)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		projectID, siteID, recordID, eventType, title, toJSONB(before), toJSONB(after))
	return err
}

// PruneEvents 事件保留策略：最多保留 keep 条，且删除超过 days 天的记录。// 返回删除条数。keep<=0 时只按时间清理。
func (a *AssetRepo) PruneEvents(ctx context.Context, keep, days int) (int64, error) {
	if days <= 0 {
		days = 7
	}
	tag, err := a.r.pool.Exec(ctx, `
WITH ranked AS (
  SELECT id, created_at, row_number() OVER (ORDER BY created_at DESC, id DESC) AS rn
    FROM asset_events
)
DELETE FROM asset_events e
 USING ranked r
 WHERE e.id = r.id
   AND (($1 > 0 AND r.rn > $1) OR e.created_at < now() - make_interval(days => $2::int))`,
		keep, days)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
