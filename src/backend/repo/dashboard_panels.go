package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// DashboardPanelsRepo 仪表盘扩展看板的聚合查询。
// 只读展示层：采集管道 / 项目资产分布 / 接口面 / JS 密钥审计命中。
// 不触发任何扫描动作——漏洞保持默认不开，这里只是把已落库的数据摆出来。
type DashboardPanelsRepo struct{ r *Repo }

func NewDashboardPanelsRepo() *DashboardPanelsRepo {
	return &DashboardPanelsRepo{r: defaultRepo}
}

// Panels 一次返回全部扩展看板数据，避免前端多个请求各查一轮。
func (d *DashboardPanelsRepo) Panels(ctx context.Context) (map[string]any, error) {
	collection, err := d.Collection(ctx)
	if err != nil {
		return nil, err
	}
	projects, err := d.ProjectBreakdown(ctx)
	if err != nil {
		return nil, err
	}
	routes, err := d.RouteSurface(ctx)
	if err != nil {
		return nil, err
	}
	jsSecrets, err := d.JSSecrets(ctx)
	if err != nil {
		return nil, err
	}
	caps, err := d.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	changes, err := d.AssetChanges(ctx)
	if err != nil {
		return nil, err
	}
	siteStatus, err := d.SiteStatus(ctx)
	if err != nil {
		return nil, err
	}
	engine, err := d.EngineUsage(ctx)
	if err != nil {
		return nil, err
	}
	tech, err := d.TechTop(ctx)
	if err != nil {
		return nil, err
	}
	ports, err := d.PortTop(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"collection":   collection,
		"projects":     projects,
		"routes":       routes,
		"js_secrets":   jsSecrets,
		"capabilities": caps,
		"changes":      changes,
		"site_status":  siteStatus,
		"engine_usage": engine,
		"tech_top":     tech,
		"port_top":     ports,
	}, nil
}

// AssetChanges 资产变化事件：近 24h 分类计数 + 最近事件流（站点变化是我
// 们最关心的动态——新增、属性变化、内容变更都在这张表里）。
func (d *DashboardPanelsRepo) AssetChanges(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	counts := map[string]int64{}
	rows, err := d.r.pool.Query(ctx, `
		SELECT event_type, count(*)
		FROM asset_events
		WHERE created_at >= now() - interval '24 hours'
		GROUP BY event_type`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var typ string
		var n int64
		if err := rows.Scan(&typ, &n); err != nil {
			rows.Close()
			return nil, err
		}
		counts[typ] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out["counts_24h"] = counts

	type changeEvt struct {
		EventType string     `json:"event_type"`
		Title     string     `json:"title"`
		SiteID    int64      `json:"site_id"`
		Host      string     `json:"host"`
		Project   string     `json:"project"`
		ProjectID int64      `json:"project_id"`
		CreatedAt *time.Time `json:"created_at"`
	}
	recent := []changeEvt{}
	rows, err = d.r.pool.Query(ctx, `
		SELECT e.event_type, e.title, e.site_id, s.host, p.name, p.id, e.created_at
		FROM asset_events e
		JOIN sites s ON s.id = e.site_id
		JOIN projects p ON p.id = e.project_id
		ORDER BY e.created_at DESC LIMIT 8`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e changeEvt
		if err := rows.Scan(&e.EventType, &e.Title, &e.SiteID, &e.Host, &e.Project, &e.ProjectID, &e.CreatedAt); err != nil {
			return nil, err
		}
		recent = append(recent, e)
	}
	out["recent"] = recent

	return out, rows.Err()
}

// SiteStatus 站点存活与健康度分布：状态码分桶 + 巡检状态分桶。
func (d *DashboardPanelsRepo) SiteStatus(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	httpBuckets := map[string]int64{}
	rows, err := d.r.pool.Query(ctx, `
		SELECT CASE
		         WHEN http_status BETWEEN 200 AND 299 THEN '2xx'
		         WHEN http_status BETWEEN 300 AND 399 THEN '3xx'
		         WHEN http_status IN (401, 403) THEN 'auth'
		         WHEN http_status = 404 THEN '404'
		         WHEN http_status BETWEEN 500 AND 599 THEN '5xx'
		         ELSE 'unknown'
		       END AS bucket, count(*)
		FROM sites GROUP BY bucket`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var bucket string
		var n int64
		if err := rows.Scan(&bucket, &n); err != nil {
			rows.Close()
			return nil, err
		}
		httpBuckets[bucket] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out["http_buckets"] = httpBuckets

	states := map[string]int64{}
	rows, err = d.r.pool.Query(ctx, `SELECT state, count(*) FROM sites GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var n int64
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		states[state] = n
	}
	out["states"] = states

	return out, rows.Err()
}

// TechTop 站点指纹技术栈 TOP（sites.tech 汇总，反映指纹规则的实战命中）。
func (d *DashboardPanelsRepo) TechTop(ctx context.Context) ([]map[string]any, error) {
	rows, err := d.r.pool.Query(ctx, `
		SELECT t, count(*)
		FROM (SELECT jsonb_array_elements_text(tech) AS t FROM sites WHERE jsonb_array_length(tech) > 0) x
		GROUP BY t ORDER BY count(*) DESC LIMIT 8`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"name": name, "count": n})
	}
	return out, rows.Err()
}

// PortTop 站点端口分布 TOP（非标端口的暴露面观察）。
func (d *DashboardPanelsRepo) PortTop(ctx context.Context) ([]map[string]any, error) {
	rows, err := d.r.pool.Query(ctx, `
		SELECT port, count(*) FROM sites GROUP BY port ORDER BY count(*) DESC LIMIT 6`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var port int64
		var n int64
		if err := rows.Scan(&port, &n); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"port": port, "count": n})
	}
	return out, rows.Err()
}

// EngineUsage 测绘引擎近 7 天查询用量（配额消耗观察）。
func (d *DashboardPanelsRepo) EngineUsage(ctx context.Context) ([]map[string]any, error) {
	rows, err := d.r.pool.Query(ctx, `
		SELECT engine, coalesce(sum(queries), 0)
		FROM engine_query_usage
		WHERE day >= current_date - 6
		GROUP BY engine ORDER BY sum(queries) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var engine string
		var n int64
		if err := rows.Scan(&engine, &n); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"engine": engine, "queries": n})
	}
	return out, rows.Err()
}

// Capabilities 平台内置能力盘点：字典/指纹/POC/漏洞情报/GitHub 泄露
// 监控/站点验证/关联关系/数字资产/企业实体。只读计数，不触发任何任务。
func (d *DashboardPanelsRepo) Capabilities(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	// 字典：套数 / 词条总量 / 自学习待晋升热词（未拒绝且未晋升）
	var dictSets, dictWords, learning int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM dictionaries),
		       (SELECT coalesce(sum(line_count),0) FROM dictionaries),
		       (SELECT count(*) FROM dict_learning WHERE NOT denied AND promoted_at IS NULL)
		`).Scan(&dictSets, &dictWords, &learning); err != nil {
		return nil, err
	}
	out["dict_sets"] = dictSets
	out["dict_words"] = dictWords
	out["dict_learning_pending"] = learning

	// 指纹：规则 / 来源 / 近 24h 命中
	var fpRules, fpSources, fpHits24 int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM fingerprint_rules),
		       (SELECT count(*) FROM fingerprint_sources),
		       (SELECT count(*) FROM fingerprint_hits WHERE observed_at >= now() - interval '24 hours')
		`).Scan(&fpRules, &fpSources, &fpHits24); err != nil {
		return nil, err
	}
	out["fingerprint_rules"] = fpRules
	out["fingerprint_sources"] = fpSources
	out["fingerprint_hits_24h"] = fpHits24

	// POC：启用 / 总量
	var pocsEnabled, pocsTotal int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE enabled), count(*) FROM pocs
		`).Scan(&pocsEnabled, &pocsTotal); err != nil {
		return nil, err
	}
	out["pocs_enabled"] = pocsEnabled
	out["pocs_total"] = pocsTotal

	// 漏洞情报：总量 / 近 7 天入库
	var intelTotal, intel7d int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE created_at >= now() - interval '7 days')
		FROM vuln_intel`).Scan(&intelTotal, &intel7d); err != nil {
		return nil, err
	}
	out["intel_total"] = intelTotal
	out["intel_7d"] = intel7d

	// GitHub 泄露监控：规则 / 命中
	var leakRules, leakFindings int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM github_monitor_rules),
		       (SELECT count(*) FROM github_leak_findings)
		`).Scan(&leakRules, &leakFindings); err != nil {
		return nil, err
	}
	out["github_leak_rules"] = leakRules
	out["github_leak_findings"] = leakFindings

	// 站点验证（近 24h 复核次数）/ 资产关联 / 数字资产 / 企业实体
	var verif24, relationsN, digitalN, entitiesN int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM verifications WHERE observed_at >= now() - interval '24 hours'),
		       (SELECT count(*) FROM relations),
		       (SELECT count(*) FROM digital_assets),
		       (SELECT count(*) FROM enterprise_entities)
		`).Scan(&verif24, &relationsN, &digitalN, &entitiesN); err != nil {
		return nil, err
	}
	out["verifications_24h"] = verif24
	out["relations"] = relationsN
	out["digital_assets"] = digitalN
	out["enterprise_entities"] = entitiesN

	return out, nil
}

// Collection 采集管道近 24h 健康度：种子收集队列、发现轮、站点巡检。
func (d *DashboardPanelsRepo) Collection(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	// 种子收集：按状态计数 + 发现数（found 是各种子展开出的新域候选量）
	jobs := map[string]int64{}
	found24 := int64(0)
	rows, err := d.r.pool.Query(ctx, `
		SELECT status, count(*), coalesce(sum(found),0)
		FROM seed_collection_jobs
		WHERE created_at >= now() - interval '24 hours'
		GROUP BY status`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status string
		var n, found int64
		if err := rows.Scan(&status, &n, &found); err != nil {
			rows.Close()
			return nil, err
		}
		jobs[status] = n
		found24 += found
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out["seed_jobs"] = jobs
	out["seed_found_24h"] = found24

	// 发现轮：24h 轮次与新发现，外加最近一轮的来源分布
	var runs24, new24 int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*), coalesce(sum(new_count),0)
		FROM discovery_runs
		WHERE ran_at >= now() - interval '24 hours'`).Scan(&runs24, &new24); err != nil {
		return nil, err
	}
	out["discovery_runs_24h"] = runs24
	out["discovery_new_24h"] = new24

	var lastRan *time.Time
	var lastCtlog, lastEngines, lastNew int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT ran_at, from_ctlog, from_engines, new_count
		FROM discovery_runs ORDER BY ran_at DESC LIMIT 1`).Scan(
		&lastRan, &lastCtlog, &lastEngines, &lastNew,
	); err == nil {
		out["last_discovery"] = map[string]any{
			"ran_at": lastRan, "from_ctlog": lastCtlog,
			"from_engines": lastEngines, "new_count": lastNew,
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		// 无任何发现轮时保持缺省，不算错误
		return nil, err
	}

	// 巡检：可达站点 / 24h 内巡检过 / 24h 内内容变更
	var reachable, checked24, changed24 int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'reachable'),
		       count(*) FILTER (WHERE content_checked_at >= now() - interval '24 hours'),
		       count(*) FILTER (WHERE content_changed_at >= now() - interval '24 hours')
		FROM sites`).Scan(&reachable, &checked24, &changed24); err != nil {
		return nil, err
	}
	out["watch_reachable"] = reachable
	out["watch_checked_24h"] = checked24
	out["watch_changed_24h"] = changed24

	return out, nil
}

// ProjectBreakdown 每个项目的资产/采集/接口面一行汇总。
func (d *DashboardPanelsRepo) ProjectBreakdown(ctx context.Context) ([]map[string]any, error) {
	rows, err := d.r.pool.Query(ctx, `
		SELECT p.id, p.name, coalesce(p.code,''),
		       (SELECT count(*) FROM seeds sd WHERE sd.project_id = p.id),
		       (SELECT count(*) FROM sites s WHERE s.project_id = p.id),
		       (SELECT count(*) FROM sites s WHERE s.project_id = p.id AND s.state = 'reachable'),
		       (SELECT count(*) FROM sites s WHERE s.project_id = p.id
		         AND s.content_checked_at >= now() - interval '24 hours'),
		       (SELECT count(*) FROM sites s WHERE s.project_id = p.id
		         AND s.content_changed_at >= now() - interval '24 hours'),
		       (SELECT count(*) FROM site_routes r WHERE r.project_id = p.id),
		       (SELECT count(*) FROM asset_candidates c WHERE c.project_id = p.id AND c.status = 'pending'),
		       (SELECT count(*) FROM seed_collection_jobs j
		         WHERE j.project_id = p.id AND j.status IN ('queued','running')),
		       (SELECT max(d.ran_at) FROM discovery_runs d WHERE d.project_id = p.id)
		FROM projects p ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, code string
		var seeds, sites, reachable, checked24, changed24, routesN, pending, collecting int64
		var lastRan *time.Time
		if err := rows.Scan(&id, &name, &code, &seeds, &sites, &reachable,
			&checked24, &changed24, &routesN, &pending, &collecting, &lastRan); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "code": code,
			"seeds": seeds, "sites": sites, "reachable": reachable,
			"checked_24h": checked24, "changed_24h": changed24,
			"routes": routesN, "pending_candidates": pending,
			"collecting": collecting, "last_discovery_at": lastRan,
		})
	}
	return out, rows.Err()
}

// RouteSurface 爬虫/JS 接口提取产出的路由面统计。
func (d *DashboardPanelsRepo) RouteSurface(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	var total, distinctPaths int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*), count(DISTINCT path) FROM site_routes`).Scan(&total, &distinctPaths); err != nil {
		return nil, err
	}
	out["total"] = total
	out["distinct_paths"] = distinctPaths

	methods := map[string]int64{}
	if rows, err := d.r.pool.Query(ctx, `
		SELECT method, count(*) FROM site_routes GROUP BY method ORDER BY count(*) DESC`); err == nil {
		for rows.Next() {
			var method string
			var n int64
			if rows.Scan(&method, &n) == nil {
				methods[method] = n
			}
		}
		rows.Close()
	}
	out["methods"] = methods

	type hostRoutes struct {
		Host   string `json:"host"`
		Routes int64  `json:"routes"`
	}
	topHosts := []hostRoutes{}
	rows, err := d.r.pool.Query(ctx, `
		SELECT s.host, count(*)
		FROM site_routes r JOIN sites s ON s.id = r.site_id
		GROUP BY s.host ORDER BY count(*) DESC LIMIT 8`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h hostRoutes
		if err := rows.Scan(&h.Host, &h.Routes); err != nil {
			return nil, err
		}
		topHosts = append(topHosts, h)
	}
	out["top_hosts"] = topHosts

	return out, rows.Err()
}

// JSSecrets JS 密钥审计命中（JSAuditModule 产出，type=js_secret）。
// 纯展示：审计只在扫描任务里随爬虫下载 JS 发生，这里不触发任何请求。
func (d *DashboardPanelsRepo) JSSecrets(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	var total int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*) FROM vulnerabilities WHERE type = 'js_secret'`).Scan(&total); err != nil {
		return nil, err
	}
	out["total"] = total

	rows, err := d.r.pool.Query(ctx, `
		SELECT coalesce(name,''), coalesce(target,''), severity, created_at
		FROM vulnerabilities WHERE type = 'js_secret'
		ORDER BY created_at DESC LIMIT 5`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type secretHit struct {
		Name      string     `json:"name"`
		Target    string     `json:"target"`
		Severity  string     `json:"severity"`
		CreatedAt *time.Time `json:"created_at"`
	}
	recent := []secretHit{}
	for rows.Next() {
		var h secretHit
		if err := rows.Scan(&h.Name, &h.Target, &h.Severity, &h.CreatedAt); err != nil {
			return nil, err
		}
		recent = append(recent, h)
	}
	out["recent"] = recent

	return out, rows.Err()
}
