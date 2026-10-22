package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/internal/recon/score"
)

// 资产风险评分（T4）。评分逻辑本身是 internal/recon/score 的纯函数；
// 这里只负责把站点当前能观测到的字段喂进去：
//
//	开放端口      raw_records 里该站点出现过的端口（不是全端口扫描结果）
//	标题/技术栈    sites.title / sites.tech
//	HTTP 结论     sites.http_status / state / verification_status / verified_at
//	漏洞实证      vulnerabilities.target 的 host 部分与 sites.host 匹配
//
// 没有数据来源的维度（TLS、安全响应头、目录列表、归属责任人）一律留空，
// 不靠默认值加分。CDN 归属尚未接入，EdgeType 传 "unknown" 而不是空串，
// 避免 score 把「未解析」误当成「确认无 CDN」而给所有资产 +5。

type riskInputRow struct {
	ID                 int64
	Host               string
	Title              string
	Tech               []string
	HTTPStatus         int
	State              string
	VerificationStatus string
	Verified           bool
	Ports              []int
	Server             string
}

type vulnStat struct {
	Severity int // 0 无；1 info .. 5 critical
	Count    int
}

// riskOrder 是排序用的中间结构，抽出来是为了单测排序口径。
type riskOrder struct {
	ID      int64
	Score   int
	Level   string
	Factors []RiskFactor
}

// sortByRisk 按分数倒序；同分时 id 倒序，保证分页稳定（不会因为同分抖动）。
func sortByRisk(rows []riskOrder) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].ID > rows[j].ID
	})
}

const riskSelect = `s.id, s.host, coalesce(s.title,''), s.tech, s.http_status, s.state,
	s.verification_status, (s.verified_at IS NOT NULL),
	coalesce(rr.ports, '[]'::jsonb), coalesce(rr.server, '')`

// riskFrom 把 raw_records 的端口与 Server 预聚合成一行，避免按站点逐行子查询。
const riskFrom = `FROM sites s
	JOIN projects p ON p.id = s.project_id
	LEFT JOIN (
		SELECT site_id, jsonb_agg(DISTINCT port) AS ports, max(nullif(server, '')) AS server
		  FROM raw_records
		 WHERE site_id IS NOT NULL
		 GROUP BY site_id
	) rr ON rr.site_id = s.id`

func (a *AssetRepo) queryRiskInputs(ctx context.Context, cond string, args []any) ([]riskInputRow, error) {
	stmt := fmt.Sprintf("SELECT %s %s WHERE %s", riskSelect, riskFrom, cond)
	rows, err := a.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("查询风险评分输入失败: %w", err)
	}
	defer rows.Close()

	out := make([]riskInputRow, 0, 64)
	for rows.Next() {
		var r riskInputRow
		var tech, ports []byte
		if err := rows.Scan(&r.ID, &r.Host, &r.Title, &tech, &r.HTTPStatus, &r.State,
			&r.VerificationStatus, &r.Verified, &ports, &r.Server); err != nil {
			return nil, fmt.Errorf("解析风险评分输入失败: %w", err)
		}
		if len(tech) > 0 {
			_ = json.Unmarshal(tech, &r.Tech)
		}
		if len(ports) > 0 {
			_ = json.Unmarshal(ports, &r.Ports)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// vulnStatsByHost 按站点 host 汇总未关闭漏洞的最高等级与条数。
// target 可能是 host、host:port 或完整 URL，统一取 host 部分再比较。
func (a *AssetRepo) vulnStatsByHost(ctx context.Context, hosts []string) (map[string]vulnStat, error) {
	out := map[string]vulnStat{}
	if len(hosts) == 0 {
		return out, nil
	}
	const stmt = `
WITH v AS (
	SELECT lower(CASE WHEN position('://' in target) > 0
	                  THEN split_part(split_part(target, '://', 2), '/', 1)
	                  ELSE split_part(target, '/', 1) END) AS hostport,
	       CASE severity
	         WHEN 'critical' THEN 5
	         WHEN 'high'     THEN 4
	         WHEN 'medium'   THEN 3
	         WHEN 'low'      THEN 2
	         ELSE 1
	       END AS rank
	  FROM vulnerabilities
	 WHERE status NOT IN ('fixed', 'ignored', 'false_positive')
)
SELECT lower(h.host), max(v.rank)::int, count(*)::int
  FROM unnest($1::text[]) AS h(host)
  JOIN v ON v.hostport = lower(h.host)
        OR left(v.hostport, length(lower(h.host)) + 1) = lower(h.host) || ':'
 GROUP BY lower(h.host)`
	rows, err := a.r.pool.Query(ctx, stmt, hosts)
	if err != nil {
		return nil, fmt.Errorf("查询漏洞等级失败: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var host string
		var st vulnStat
		if err := rows.Scan(&host, &st.Severity, &st.Count); err != nil {
			return nil, fmt.Errorf("解析漏洞等级失败: %w", err)
		}
		out[host] = st
	}
	return out, rows.Err()
}

// computeSiteRisk 是「观测字段 → 评分」的唯一转换点，保持 score.Compute 为纯函数。
func computeSiteRisk(r riskInputRow, vs vulnStat) (int, string, []RiskFactor) {
	defaultPage, directoryListing, errorPage := webSurfaceFlags(r.Title)
	total, level, raw := score.Compute(score.Input{
		OpenPorts:        r.Ports,
		EdgeType:         "unknown", // CDN 归属未接入，不按「无 CDN」加分
		Server:           r.Server,
		Title:            r.Title,
		Fingerprints:     r.Tech,
		HTTPStatus:       r.HTTPStatus,
		HTTPSeen:         r.Verified || r.HTTPStatus > 0 || r.State == "reachable" || r.VerificationStatus == "verified",
		VulnSeverity:     vs.Severity,
		VulnCount:        vs.Count,
		HasOwner:         true, // 归属字段尚未建模，不能据此判定影子资产
		DefaultPage:      defaultPage,
		DirectoryListing: directoryListing,
		ErrorPage:        errorPage,
	})
	factors := make([]RiskFactor, 0, len(raw))
	for _, f := range raw {
		factors = append(factors, RiskFactor{Factor: f.Factor, Points: f.Points, Detail: f.Detail})
	}
	return total, level, factors
}

// attachRisk 给当前页的站点补上 risk_score / priority。
func (a *AssetRepo) attachRisk(ctx context.Context, sites []*Site) error {
	if len(sites) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(sites))
	hosts := make([]string, 0, len(sites))
	for _, s := range sites {
		ids = append(ids, s.ID)
		hosts = append(hosts, strings.ToLower(s.Host))
	}
	inputs, err := a.queryRiskInputs(ctx, "s.id = ANY($1)", []any{ids})
	if err != nil {
		return err
	}
	stats, err := a.vulnStatsByHost(ctx, hosts)
	if err != nil {
		return err
	}
	byID := make(map[int64]riskInputRow, len(inputs))
	for _, r := range inputs {
		byID[r.ID] = r
	}
	for _, s := range sites {
		s.RiskScore, s.Priority, s.RiskFactors = computeSiteRisk(byID[s.ID], stats[strings.ToLower(s.Host)])
	}
	return nil
}

// listSiteRowsByRisk 按评分全局排序后再取当前页。
// 评分依赖观测字段而不是已落库的列，所以只能把候选行全部算完再切片；
// 这是 sort=risk 的显式代价，默认排序不受影响。
func (a *AssetRepo) listSiteRowsByRisk(ctx context.Context, w *whereBuilder, q AssetQuery) (any, int64, error) {
	var total int64
	if err := a.r.pool.QueryRow(ctx,
		"SELECT count(*) FROM sites s JOIN projects p ON p.id = s.project_id WHERE "+w.String(),
		w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计资产失败: %w", err)
	}
	if total == 0 {
		return []*Site{}, 0, nil
	}

	inputs, err := a.queryRiskInputs(ctx, w.String(), w.args)
	if err != nil {
		return nil, 0, err
	}
	hosts := make([]string, 0, len(inputs))
	for _, r := range inputs {
		hosts = append(hosts, strings.ToLower(r.Host))
	}
	stats, err := a.vulnStatsByHost(ctx, hosts)
	if err != nil {
		return nil, 0, err
	}

	order := make([]riskOrder, 0, len(inputs))
	for _, r := range inputs {
		sc, level, factors := computeSiteRisk(r, stats[strings.ToLower(r.Host)])
		order = append(order, riskOrder{ID: r.ID, Score: sc, Level: level, Factors: factors})
	}
	sortByRisk(order)

	offset := (q.Page - 1) * q.PageSize
	if offset >= len(order) {
		return []*Site{}, total, nil
	}
	end := offset + q.PageSize
	if end > len(order) {
		end = len(order)
	}
	page := order[offset:end]
	ids := make([]int64, 0, len(page))
	riskByID := make(map[int64]riskOrder, len(page))
	for _, o := range page {
		ids = append(ids, o.ID)
		riskByID[o.ID] = o
	}

	stmt := fmt.Sprintf(`SELECT %s FROM sites s JOIN projects p ON p.id = s.project_id
		WHERE s.id = ANY($1) ORDER BY array_position($1::bigint[], s.id)`, siteColumns)
	rows, err := a.r.pool.Query(ctx, stmt, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("查询资产失败: %w", err)
	}
	defer rows.Close()

	out := make([]*Site, 0, len(ids))
	for rows.Next() {
		s, err := scanSite(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("解析资产失败: %w", err)
		}
		if r, ok := riskByID[s.ID]; ok {
			s.RiskScore, s.Priority, s.RiskFactors = r.Score, r.Level, r.Factors
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// defaultPagePatterns 是默认/示例页标题特征：默认部署通常版本旧、配置松。
var defaultPagePatterns = []string{
	"welcome to openresty", "welcome to nginx", "apache2 ubuntu default page",
	"apache2 debian default page", "it works!", "test page for the apache http server",
	"iis windows server", "welcome to tomcat", "welcome to jboss", "jboss as",
	"wildfly", "welcome to centos", "default web site page", "site not found",
	"no website is configured",
}

// errorPagePatterns 是错误/调试页标题特征：暴露框架、堆栈或 SQL 方言。
var errorPagePatterns = []string{
	"whitelabel error page", "whitelabel", "http status 500", "internal server error",
	"stack trace", "traceback", "werkzeug debugger", "phpinfo()", "fatal error",
	"sql syntax", "ora-0", "warning: mysql", "undefined index", "notice: undefined",
}

// webSurfaceFlags 从标题推导 Web 卫生三个弱信号；没有标题时全部为 false。
func webSurfaceFlags(title string) (defaultPage, directoryListing, errorPage bool) {
	t := strings.ToLower(strings.TrimSpace(title))
	if t == "" {
		return false, false, false
	}
	directoryListing = strings.HasPrefix(t, "index of /") || strings.Contains(t, "directory listing for")
	for _, p := range defaultPagePatterns {
		if strings.Contains(t, p) {
			defaultPage = true
			break
		}
	}
	for _, p := range errorPagePatterns {
		if strings.Contains(t, p) {
			errorPage = true
			break
		}
	}
	return defaultPage, directoryListing, errorPage
}
