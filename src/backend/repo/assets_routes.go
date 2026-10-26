package repo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 资产路由：爬虫采到的 path 粒度入口。
//
// site_endpoints 是「协议+端口」入口，site_routes 是「方法+路径」入口。
// 同一站点下 (method, path) 唯一，重复采集只刷新 last_seen，不新增行。

type SiteRoute struct {
	ID         int64     `json:"id"`
	SiteID     int64     `json:"site_id"`
	ProjectID  int64     `json:"project_id"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	Source     string    `json:"source"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// RouteInput 是一条待写入的路由。调用方负责把完整 URL 解析成 method+path。
type RouteInput struct {
	Method     string
	Path       string
	StatusCode int
}

// SiteIDByHostAny 按 host 找站点（不限项目）。
// 爬虫结果通常只有 URL，没有项目上下文；站点 host 在库内基本唯一，
// 命中多个时取最早创建的那个。
func (a *AssetRepo) SiteIDByHostAny(ctx context.Context, host string) (int64, int64, error) {
	if a == nil || a.r == nil {
		return 0, 0, errUninitialized()
	}
	var siteID, projectID int64
	err := a.r.pool.QueryRow(ctx,
		`SELECT id, project_id FROM sites WHERE host = $1 ORDER BY id LIMIT 1`, host).
		Scan(&siteID, &projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, err
	}
	return siteID, projectID, nil
}

// isJunkRouteStatus 爬虫实测确认「路径不存在/服务不可用」的状态码。
// 404/410 是明确不存在；5xx 是服务端异常，不可信。401/403 是接口存在但
// 有鉴权——高价值线索，保留。状态码 0 表示只从 JS 里提取了路径、还没
// 实测，是候选不是垃圾，同样保留。
func isJunkRouteStatus(code int) bool {
	return code == 404 || code == 410 || (code >= 500 && code <= 599)
}

// SiteIDByHostWithStatus 按 host 找站点并带回当前 http_status，
// 供爬虫入库前做死站守卫（404/410 站点的爬取结果整体是垃圾）。
func (a *AssetRepo) SiteIDByHostWithStatus(ctx context.Context, host string) (int64, int64, int, error) {
	if a == nil || a.r == nil {
		return 0, 0, 0, errUninitialized()
	}
	var siteID, projectID, status int64
	err := a.r.pool.QueryRow(ctx,
		`SELECT id, project_id, http_status FROM sites WHERE host = $1 ORDER BY id LIMIT 1`, host).
		Scan(&siteID, &projectID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, 0, err
	}
	return siteID, projectID, int(status), nil
}

// SiteHTTPStatus 查站点当前 http_status（巡检慢爬守卫用）。
func (a *AssetRepo) SiteHTTPStatus(ctx context.Context, siteID int64) (int, error) {
	if a == nil || a.r == nil {
		return 0, errUninitialized()
	}
	var status int64
	err := a.r.pool.QueryRow(ctx,
		`SELECT http_status FROM sites WHERE id = $1`, siteID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return int(status), err
}

// SiteDeadByStatus 站点状态是否属于死站：实测 404/410，爬取与慢爬都应跳过。
func SiteDeadByStatus(status int) bool {
	return status == 404 || status == 410
}

// UpsertSiteRoutes 批量写路由，返回实际处理条数。同一批内 (method,path) 会先去重。
// 数据清洗：实测 404/410/5xx 的路径反向删除（爬到过但现在死了的不该再展示）；
// 状态码 0（未实测候选）不覆盖已验证的状态码。
func (a *AssetRepo) UpsertSiteRoutes(ctx context.Context, siteID, projectID int64, source string, routes []RouteInput) (int, error) {
	if a == nil || a.r == nil {
		return 0, errUninitialized()
	}
	if siteID <= 0 || len(routes) == 0 {
		return 0, nil
	}

	seen := make(map[string]bool, len(routes))
	clean := make([]RouteInput, 0, len(routes))
	for _, r := range routes {
		method := strings.ToUpper(strings.TrimSpace(r.Method))
		if method == "" {
			method = "GET"
		}
		path := strings.TrimSpace(r.Path)
		if path == "" {
			path = "/"
		}
		key := method + "\x00" + path
		if seen[key] {
			continue
		}
		seen[key] = true
		clean = append(clean, RouteInput{Method: method, Path: path, StatusCode: r.StatusCode})
	}

	batch := &pgx.Batch{}
	dropped := 0
	for _, r := range clean {
		if isJunkRouteStatus(r.StatusCode) {
			batch.Queue(`
				DELETE FROM site_routes WHERE site_id = $1 AND method = $2 AND path = $3`,
				siteID, r.Method, r.Path)
			dropped++
			continue
		}
		batch.Queue(`
			INSERT INTO site_routes (site_id, project_id, method, path, status_code, source)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (site_id, method, path) DO UPDATE SET
				status_code = CASE WHEN EXCLUDED.status_code > 0
					THEN EXCLUDED.status_code ELSE site_routes.status_code END,
				source      = EXCLUDED.source,
				last_seen   = now()`,
			siteID, projectID, r.Method, r.Path, r.StatusCode, source)
	}

	br := a.r.pool.SendBatch(ctx, batch)
	for range clean {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return 0, fmt.Errorf("写入路由失败: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return 0, err
	}
	return len(clean) - dropped, nil
}

// ListSiteRoutes 某站点的路由，按最近发现排序。
func (a *AssetRepo) ListSiteRoutes(ctx context.Context, siteID int64, limit int) ([]*SiteRoute, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := a.r.pool.Query(ctx, `
		SELECT id, site_id, project_id, method, path, status_code, source, first_seen, last_seen
		FROM site_routes WHERE site_id = $1
		ORDER BY last_seen DESC, id DESC LIMIT $2`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSiteRoutes(rows)
}

// RoutesForSites 批量取多个站点的路由，供资产星图一次性加载。
// perSite 限制每个站点最多返回多少条（默认 20）：爬虫很容易采出上千条路径，
// 全量塞进图会把画布撑爆。
func (a *AssetRepo) RoutesForSites(ctx context.Context, siteIDs []int64, perSite int) ([]*SiteRoute, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if len(siteIDs) == 0 {
		return []*SiteRoute{}, nil
	}
	if perSite <= 0 || perSite > 200 {
		perSite = 20
	}
	rows, err := a.r.pool.Query(ctx, `
		SELECT id, site_id, project_id, method, path, status_code, source, first_seen, last_seen
		FROM (
			SELECT *, row_number() OVER (PARTITION BY site_id ORDER BY last_seen DESC, id DESC) AS rn
			FROM site_routes WHERE site_id = ANY($1)
		) t WHERE rn <= $2
		ORDER BY site_id, last_seen DESC, id DESC`, siteIDs, perSite)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSiteRoutes(rows)
}

func scanSiteRoutes(rows pgx.Rows) ([]*SiteRoute, error) {
	out := make([]*SiteRoute, 0, 64)
	for rows.Next() {
		var r SiteRoute
		if err := rows.Scan(&r.ID, &r.SiteID, &r.ProjectID, &r.Method, &r.Path,
			&r.StatusCode, &r.Source, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// ParseRouteURL 把完整 URL 拆成 method + path。
// 查询串保留在 path 里：接口路由经常靠参数区分，丢了就分不清 /api?id=1 和 /api?id=2。
func ParseRouteURL(raw, method string) (path string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p, true
}

// authPortalURLRe 认证入口 URL 特征：路径含登录/SSO/OAuth/CAS/SAML/auth 段。
// 前后要求非字母数字边界——/author、/authorize 不误报（auth 后跟字母），oauth2.html 命中。
var authPortalURLRe = regexp.MustCompile(`(?i)(^|[^a-z0-9])(login|logon|signin|sign-in|sso|oauth|saml|cas|auth)([^a-z]|$)`)

// IsAuthPortalURL 报告 URL 是否携带认证入口特征（爬虫发现的登录/SSO 链接）。
func IsAuthPortalURL(raw string) bool {
	return authPortalURLRe.MatchString(raw)
}

// MarkAuthPortals 给爬虫发现认证入口的站点追加 Auth-Portal 指纹标签，
// 供资产页/指纹评分按「重点资产：有认证入口」筛选。幂等：已带标签的站点跳过。
func (a *AssetRepo) MarkAuthPortals(ctx context.Context, projectID int64, hosts []string) (int64, error) {
	if len(hosts) == 0 {
		return 0, nil
	}
	tag, err := a.r.pool.Exec(ctx, `
update sites set
	tech = (coalesce(tech, '[]'::jsonb) || '["Auth-Portal"]'::jsonb),
	tech_status = 'done'
where project_id = $1 and host = any($2)
  and coalesce(tech::text, '') not like '%Auth-Portal%'`, projectID, hosts)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
