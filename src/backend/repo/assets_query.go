package repo

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// 资产列表的多维查询。对应 v4 §11.4 的三层正交维度：
//
//	view     看哪一类（clues / candidates / lost / 聚类视图）
//	kind     看什么粒度（site / domain / ip）
//	catalog  算不算已确认（all / verified / candidates）
//
// 三层是笛卡尔组合，不是一棵树；切换时的参数清理在前端做，后端不做兜底。

// AssetQuery 是列表查询参数。空值一律取缺省（kind=site / catalog=all / view=""）。
type AssetQuery struct {
	ProjectID int64
	Q         string
	Kind      string // site | domain | ip
	Catalog   string // all | verified | candidates
	View      string // "" | clues | candidates | lost | icons | technologies | apps | media
	SiteGroup bool   // true=归并到站点，false=展开到入口（仅 kind=site 有意义）
	Page      int
	PageSize  int
}

// ConnectivityPolicy 是连通性与清理策略，随列表响应下发，前端不再二次请求。
type ConnectivityPolicy struct {
	FailureThreshold int  `json:"failure_threshold"`
	FirstHours       int  `json:"first_hours"`
	SecondHours      int  `json:"second_hours"`
	RepeatHours      int  `json:"repeat_hours"`
	CleanupDays      int  `json:"cleanup_days"`
	AutoCleanup      bool `json:"auto_cleanup"`
}

// AssetPage 是一次列表查询的结果。Items 的具体类型取决于 Kind：
//
//	site   → []*Site
//	domain → []*DomainRow
//	ip     → []*IPRow
type AssetPage struct {
	Items     any                 `json:"items"`
	Total     int64               `json:"total"`
	Page      int                 `json:"page"`
	PageSize  int                 `json:"page_size"`
	Kind      string              `json:"kind"`
	Catalog   string              `json:"catalog"`
	View      string              `json:"view"`
	Lifecycle string              `json:"lifecycle"`
	SiteGroup bool                `json:"site_group"`
	Supported bool                `json:"view_supported"`
	Note      string              `json:"note,omitempty"`
	Policy    *ConnectivityPolicy `json:"connectivity_policy,omitempty"`
}

// DomainRow 是域名粒度的一行。
type DomainRow struct {
	Host         string    `json:"host"`
	SiteCount    int64     `json:"site_count"`
	ProjectID    int64     `json:"project_id"`
	ProjectCode  string    `json:"project_code"`
	ProjectName  string    `json:"project_name"`
	ReachableCnt int64     `json:"reachable_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// IPRow 是 IP 粒度的一行。
type IPRow struct {
	IP          string    `json:"ip"`
	SiteCount   int64     `json:"site_count"`
	DomainCount int64     `json:"domain_count"`
	ProjectID   int64     `json:"project_id"`
	LastSeen    time.Time `json:"last_seen"`
}

// EndpointRow 是展开到入口的一行（site_group=0）。
type EndpointRow struct {
	SiteID      int64     `json:"site_id"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	Value       string    `json:"value"`
	Title       string    `json:"title"`
	HTTPStatus  int       `json:"http_status"`
	State       string    `json:"state"`
	ProjectID   int64     `json:"project_id"`
	ProjectName string    `json:"project_name"`
	RecordCount int64     `json:"record_count"`
	LastSeen    time.Time `json:"last_seen"`
}

func normalizeKind(k string) string {
	switch k {
	case "domain", "ip", "site":
		return k
	}
	return "site"
}

func normalizeCatalog(c string) string {
	switch c {
	case "verified", "candidates", "all":
		return c
	}
	return "all"
}

// whereBuilder 收集 WHERE 片段与参数，占位符从 base 开始编号（与 DSL 编译器的 base 对齐）。
type whereBuilder struct {
	parts []string
	args  []any
	next  int
}

func newWhereBuilder(base int) *whereBuilder {
	if base < 1 {
		base = 1
	}
	return &whereBuilder{next: base}
}

func (w *whereBuilder) ph() string {
	p := fmt.Sprintf("$%d", w.next)
	w.next++
	return p
}

func (w *whereBuilder) String() string {
	if len(w.parts) == 0 {
		return "1=1"
	}
	return strings.Join(w.parts, " AND ")
}

// buildAssetWhere 把三层维度与 DSL 合成 WHERE（别名固定为 s）。
func (a *AssetRepo) buildAssetWhere(q AssetQuery) (*whereBuilder, error) {
	w := newWhereBuilder(1)

	if q.ProjectID > 0 {
		w.parts = append(w.parts, "s.project_id = "+w.ph())
		w.args = append(w.args, q.ProjectID)
	}

	// catalog 不是过滤器而是统计口径：拼进 WHERE，count 与列表共用同一份条件
	switch normalizeCatalog(q.Catalog) {
	case "verified":
		w.parts = append(w.parts, "s.state = 'reachable'")
	case "candidates":
		w.parts = append(w.parts, "(s.state = 'pending' OR s.verification_status IN ('pending','failed'))")
	}

	// view 的第一批三态（聚类视图走独立接口，不在这里）
	switch q.View {
	case "lost":
		w.parts = append(w.parts, "s.state = 'lost'")
	case "clues":
		w.parts = append(w.parts, "s.verification_status = 'pending' AND s.attempts = 0")
	case "candidates":
		w.parts = append(w.parts, "(s.state = 'pending' OR s.verification_status IN ('pending','failed'))")
	}

	if strings.TrimSpace(q.Q) != "" {
		expr, args, err := BuildAssetWhereFrom(q.Q, w.next)
		if err != nil {
			return nil, err
		}
		if expr != "" {
			w.parts = append(w.parts, expr)
			w.args = append(w.args, args...)
			w.next += len(args)
		}
	}
	return w, nil
}

// unsupportedView 说明哪些视图还没做，避免前端把「空列表」误当成「没数据」。
func unsupportedView(view string) (bool, string) {
	switch view {
	case "icons":
		return false, "聚合视图请用 GET /api/assets/icons（T4 第二步）"
	case "technologies":
		return false, "聚合视图请用 GET /api/assets/technologies（T4 第二步）"
	case "apps", "media":
		return false, "APP / 新媒体数据源未接入"
	}
	return true, ""
}

// ListAssets 是资产列表的唯一入口，按 Kind 走三套 SQL。
func (a *AssetRepo) ListAssets(ctx context.Context, q AssetQuery) (*AssetPage, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 || q.PageSize > 500 {
		q.PageSize = 20
	}
	page := &AssetPage{
		Page: q.Page, PageSize: q.PageSize,
		Kind: normalizeKind(q.Kind), Catalog: normalizeCatalog(q.Catalog),
		View: q.View, SiteGroup: q.SiteGroup, Supported: true,
	}
	// site_group 只对站点粒度有意义；IP / 域名聚合本身就不可展开
	if page.Kind != "site" {
		page.SiteGroup = true
	}

	if ok, note := unsupportedView(q.View); !ok {
		page.Supported = false
		page.Note = note
		page.Items = []any{}
		page.Policy, _ = a.ConnectivityPolicy(ctx)
		return page, nil
	}

	w, err := a.buildAssetWhere(q)
	if err != nil {
		return nil, err
	}

	switch page.Kind {
	case "domain":
		page.Items, page.Total, err = a.listDomains(ctx, w, q)
	case "ip":
		page.Items, page.Total, err = a.listIPs(ctx, w, q)
	default:
		if q.SiteGroup {
			page.Items, page.Total, err = a.listSiteRows(ctx, w, q)
		} else {
			page.Items, page.Total, err = a.listEndpointRows(ctx, w, q)
		}
	}
	if err != nil {
		return nil, err
	}
	page.Policy, _ = a.ConnectivityPolicy(ctx)
	return page, nil
}

// ConnectivityPolicy 读连通性策略（单行表）。
func (a *AssetRepo) ConnectivityPolicy(ctx context.Context) (*ConnectivityPolicy, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	var p ConnectivityPolicy
	err := a.r.pool.QueryRow(ctx,
		`SELECT failure_threshold, first_hours, second_hours, repeat_hours, cleanup_days, auto_cleanup
		   FROM connectivity_policies WHERE id = 1`).
		Scan(&p.FailureThreshold, &p.FirstHours, &p.SecondHours, &p.RepeatHours, &p.CleanupDays, &p.AutoCleanup)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (a *AssetRepo) listSiteRows(ctx context.Context, w *whereBuilder, q AssetQuery) (any, int64, error) {
	cond := w.String()
	var total int64
	if err := a.r.pool.QueryRow(ctx,
		"SELECT count(*) FROM sites s JOIN projects p ON p.id = s.project_id WHERE "+cond,
		w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计资产失败: %w", err)
	}

	args := append(append([]any{}, w.args...), q.PageSize, (q.Page-1)*q.PageSize)
	stmt := fmt.Sprintf(`SELECT %s FROM sites s JOIN projects p ON p.id = s.project_id
		WHERE %s ORDER BY s.first_seen DESC, s.id DESC LIMIT $%d OFFSET $%d`,
		siteColumns, cond, len(args)-1, len(args))

	rows, err := a.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询资产失败: %w", err)
	}
	defer rows.Close()

	out := []*Site{}
	for rows.Next() {
		s, err := scanSite(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("解析资产失败: %w", err)
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

func (a *AssetRepo) listEndpointRows(ctx context.Context, w *whereBuilder, q AssetQuery) (any, int64, error) {
	cond := w.String()
	// 展开视图的口径是「唯一入口数」，同一入口采集多次只算一行
	countSQL := "SELECT count(*) FROM (SELECT DISTINCT r.host, r.port, r.protocol " +
		"FROM raw_records r JOIN sites s ON s.id = r.site_id WHERE " + cond + ") t"
	var total int64
	if err := a.r.pool.QueryRow(ctx, countSQL, w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计入口失败: %w", err)
	}

	args := append(append([]any{}, w.args...), q.PageSize, (q.Page-1)*q.PageSize)
	stmt := fmt.Sprintf(`
		SELECT coalesce(max(r.site_id),0), r.host, r.port, coalesce(max(r.protocol),''),
		       coalesce(max(r.value),''), coalesce(max(s.title),''), coalesce(max(s.http_status),0),
		       coalesce(max(s.state),''), coalesce(max(s.project_id),0), coalesce(max(p.name),''),
		       count(*), max(r.observed_at)
		  FROM raw_records r
		  JOIN sites s ON s.id = r.site_id
		  JOIN projects p ON p.id = s.project_id
		 WHERE %s
		 GROUP BY r.host, r.port, r.protocol
		 ORDER BY max(r.observed_at) DESC, r.host
		 LIMIT $%d OFFSET $%d`, cond, len(args)-1, len(args))

	rows, err := a.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询入口失败: %w", err)
	}
	defer rows.Close()

	out := []*EndpointRow{}
	for rows.Next() {
		var e EndpointRow
		if err := rows.Scan(&e.SiteID, &e.Host, &e.Port, &e.Protocol, &e.Value, &e.Title,
			&e.HTTPStatus, &e.State, &e.ProjectID, &e.ProjectName, &e.RecordCount, &e.LastSeen); err != nil {
			return nil, 0, fmt.Errorf("解析入口失败: %w", err)
		}
		out = append(out, &e)
	}
	return out, total, rows.Err()
}

func (a *AssetRepo) listDomains(ctx context.Context, w *whereBuilder, q AssetQuery) (any, int64, error) {
	cond := w.String()
	countSQL := "SELECT count(*) FROM (SELECT 1 FROM sites s WHERE " + cond + " GROUP BY s.host) t"
	var total int64
	if err := a.r.pool.QueryRow(ctx, countSQL, w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计域名失败: %w", err)
	}

	args := append(append([]any{}, w.args...), q.PageSize, (q.Page-1)*q.PageSize)
	stmt := fmt.Sprintf(`
		SELECT s.host, count(*) AS site_count, min(s.project_id),
		       min(p.code), min(p.name),
		       count(*) FILTER (WHERE s.state = 'reachable') AS reachable_count,
		       max(s.last_seen)
		  FROM sites s JOIN projects p ON p.id = s.project_id
		 WHERE %s
		 GROUP BY s.host
		 ORDER BY site_count DESC, s.host
		 LIMIT $%d OFFSET $%d`, cond, len(args)-1, len(args))

	rows, err := a.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询域名失败: %w", err)
	}
	defer rows.Close()

	out := []*DomainRow{}
	for rows.Next() {
		var d DomainRow
		if err := rows.Scan(&d.Host, &d.SiteCount, &d.ProjectID, &d.ProjectCode, &d.ProjectName,
			&d.ReachableCnt, &d.LastSeen); err != nil {
			return nil, 0, fmt.Errorf("解析域名失败: %w", err)
		}
		out = append(out, &d)
	}
	return out, total, rows.Err()
}

func (a *AssetRepo) listIPs(ctx context.Context, w *whereBuilder, q AssetQuery) (any, int64, error) {
	// IP 视图必须排除没有 IP 的站点，否则会出现一行空 IP
	cond := w.String() + " AND s.ip IS NOT NULL"
	countSQL := "SELECT count(*) FROM (SELECT 1 FROM sites s WHERE " + cond + " GROUP BY s.ip) t"
	var total int64
	if err := a.r.pool.QueryRow(ctx, countSQL, w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 IP 失败: %w", err)
	}

	args := append(append([]any{}, w.args...), q.PageSize, (q.Page-1)*q.PageSize)
	stmt := fmt.Sprintf(`
		SELECT s.ip::text, count(*) AS site_count, count(DISTINCT s.host) AS domain_count,
		       min(s.project_id), max(s.last_seen)
		  FROM sites s
		 WHERE %s
		 GROUP BY s.ip
		 ORDER BY site_count DESC, s.ip
		 LIMIT $%d OFFSET $%d`, cond, len(args)-1, len(args))

	rows, err := a.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询 IP 失败: %w", err)
	}
	defer rows.Close()

	out := []*IPRow{}
	for rows.Next() {
		var r IPRow
		if err := rows.Scan(&r.IP, &r.SiteCount, &r.DomainCount, &r.ProjectID, &r.LastSeen); err != nil {
			return nil, 0, fmt.Errorf("解析 IP 失败: %w", err)
		}
		out = append(out, &r)
	}
	return out, total, rows.Err()
}
