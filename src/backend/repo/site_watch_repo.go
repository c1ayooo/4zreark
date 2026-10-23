package repo

import (
	"context"
	"time"
)

// 站点内容巡检（SiteWatch）仓储：慢速队列的选站/记 hash/豁免。

type WatchSite struct {
	SiteID      int64      `json:"site_id"`
	ProjectID   int64      `json:"project_id"`
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	Scheme      string     `json:"scheme"`
	Title       string     `json:"title"`
	ContentHash string     `json:"content_hash"`
	TextHash    string     `json:"content_text_hash"`
	CheckedAt   *time.Time `json:"content_checked_at"`
	ChangedAt   *time.Time `json:"content_changed_at"`
}

// SelectWatchSitesSQL 选站查询。导出供集成测试按项目过滤复用——
// 全局队列被存量站点占满时，新造的夹具站点排不进 limit 页，只有同源
// 才能保证测试测的就是生产跑的 SQL。
const SelectWatchSitesSQL = `
select s.id, s.project_id, s.host, e.port, e.scheme,
       coalesce(s.title, ''), coalesce(s.content_hash, ''), coalesce(s.content_text_hash, ''),
       s.content_checked_at, s.content_changed_at
from sites s
join lateral (
	select e.port, e.scheme
	from site_endpoints e
	where e.site_id = s.id and e.scheme in ('http', 'https')
	order by (e.scheme = 'https') desc, e.port asc
	limit 1
) e on true
where s.state = 'reachable' and not s.watch_excluded
  and not exists (select 1 from projects p where p.id = s.project_id and p.collection_paused)
  and (s.content_checked_at is null or s.content_checked_at < now() - make_interval(hours => $1))`

// SelectWatchSites 选出待巡检站点：reachable、有 HTTP(S) 入口、未豁免、
// 从未查过或距上次检查超过 intervalHours。最旧优先，limit 封顶。
// 端点取同一行的 port/scheme（https 优先、端口小者优先），tcp-only 站点不参与。
func (a *AssetRepo) SelectWatchSites(ctx context.Context, intervalHours int, limit int) ([]WatchSite, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := a.r.pool.Query(ctx, SelectWatchSitesSQL+`
order by s.content_checked_at asc nulls first, s.id
limit $2`, intervalHours, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WatchSite{}
	for rows.Next() {
		var w WatchSite
		if err := rows.Scan(&w.SiteID, &w.ProjectID, &w.Host, &w.Port, &w.Scheme,
			&w.Title, &w.ContentHash, &w.TextHash, &w.CheckedAt, &w.ChangedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

type ContentHashUpdate struct {
	RawHash    string
	TextHash   string
	Changed    bool
	CheckedURL string
}

// UpdateSiteContentHash 记录一次巡检结果；changed=true 时同时盖 content_changed_at。
func (a *AssetRepo) UpdateSiteContentHash(ctx context.Context, siteID int64, u ContentHashUpdate) error {
	tag, err := a.r.pool.Exec(ctx, `
update sites set content_hash = $2, content_text_hash = $3, content_checked_at = now(),
    content_changed_at = case when $4 then now() else content_changed_at end
where id = $1`, siteID, u.RawHash, u.TextHash, u.Changed)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchSiteWatchChecked 仅推进巡检时间戳。探测失败的站点也要记账，
// 否则按 content_checked_at 最旧优先会永远排在队头，饿死其余站点。
func (a *AssetRepo) TouchSiteWatchChecked(ctx context.Context, siteID int64) error {
	_, err := a.r.pool.Exec(ctx,
		`update sites set content_checked_at = now() where id = $1`, siteID)
	return err
}

// SetSiteWatchExcluded 站点豁免/恢复巡检。
func (a *AssetRepo) SetSiteWatchExcluded(ctx context.Context, siteID int64, excluded bool) error {
	tag, err := a.r.pool.Exec(ctx,
		`update sites set watch_excluded = $2 where id = $1`, siteID, excluded)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// HasRunningWatchCrawl 查询是否已有站点巡检触发的慢爬任务在跑（全局单飞）。
// 任务名约定前缀「[站点巡检]」，running 状态即视为在跑。
func (a *AssetRepo) HasRunningWatchCrawl(ctx context.Context) (bool, error) {
	var n int64
	err := a.r.pool.QueryRow(ctx, `
select count(*) from tasks
where name like '[站点巡检]%' and status in ('pending','running')`).Scan(&n)
	return n > 0, err
}

// LastWatchCrawlForSite 查询某站点上次慢爬的创建时间（同站 24h 冷却）。
// 慢爬任务的 targets 存的是完整 URL（scheme://host:port），按前缀匹配。
func (a *AssetRepo) LastWatchCrawlForSite(ctx context.Context, projectID int64, scheme, host string) (*time.Time, error) {
	var t *time.Time
	err := a.r.pool.QueryRow(ctx, `
select max(created_at) from tasks
where project_id = $1 and name like '[站点巡检]%'
  and exists (select 1 from unnest(targets) t where t like $2 || '//' || $3 || ':%')`,
		projectID, scheme+"://", host).Scan(&t)
	if err != nil {
		return nil, err
	}
	return t, nil
}
