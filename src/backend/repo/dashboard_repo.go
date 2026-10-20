package repo

import (
	"context"
)

// DashboardRepo 收口仪表盘统计的 SQL。
// 原来 dashboard 走 Mongo 的聚合（vuln/node/task service），Mongo 移除后全部返回 nil，
// 前端读 null.total 直接崩，仪表盘白屏。这里改成一次性查 PG，缺数据也返回零值对象。
type DashboardRepo struct{ r *Repo }

func NewDashboardRepo() *DashboardRepo { return &DashboardRepo{r: defaultRepo} }

// Stats 返回四张卡片的统计，结构与前端 DashboardStats 对齐。
func (d *DashboardRepo) Stats(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	var assetTotal, assetActive, assetRecent int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE state = 'reachable'),
		       count(*) FILTER (WHERE first_seen >= now() - interval '7 days')
		FROM sites`).Scan(&assetTotal, &assetActive, &assetRecent); err != nil {
		return nil, err
	}
	out["assets"] = map[string]any{
		"total": assetTotal, "active": assetActive, "recentlyAdded": assetRecent,
		"byType": map[string]any{},
	}

	var vulnTotal, vulnOpen int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status NOT IN ('fixed','ignored','false_positive'))
		FROM vulnerabilities`).Scan(&vulnTotal, &vulnOpen); err != nil {
		return nil, err
	}
	bySeverity := map[string]int64{}
	if rows, err := d.r.pool.Query(ctx, `SELECT severity, count(*) FROM vulnerabilities GROUP BY severity`); err == nil {
		for rows.Next() {
			var sev string
			var n int64
			if rows.Scan(&sev, &n) == nil {
				bySeverity[sev] = n
			}
		}
		rows.Close()
	}
	out["vulnerabilities"] = map[string]any{"total": vulnTotal, "open": vulnOpen, "bySeverity": bySeverity}

	var taskTotal, taskRunning int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status = 'running') FROM tasks`).Scan(&taskTotal, &taskRunning); err != nil {
		return nil, err
	}
	out["tasks"] = map[string]any{"total": taskTotal, "running": taskRunning}

	var nodeTotal, nodeOnline int64
	if err := d.r.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status = 'online') FROM scanner_nodes`).Scan(&nodeTotal, &nodeOnline); err != nil {
		return nil, err
	}
	out["nodes"] = map[string]any{"total": nodeTotal, "online": nodeOnline}

	return out, nil
}

// Trends 按天统计资产/漏洞/任务新增，date 为 YYYY-MM-DD。
func (d *DashboardRepo) Trends(ctx context.Context, days int) ([]map[string]any, error) {
	if days <= 0 {
		days = 7
	}
	if days > 90 {
		days = 90
	}
	rows, err := d.r.pool.Query(ctx, `
		SELECT to_char(d::date, 'YYYY-MM-DD'),
		       (SELECT count(*) FROM sites s WHERE s.first_seen::date = d::date),
		       (SELECT count(*) FROM vulnerabilities v WHERE v.created_at::date = d::date),
		       (SELECT count(*) FROM tasks t WHERE t.created_at::date = d::date)
		FROM generate_series(current_date - ($1::int - 1), current_date, interval '1 day') AS d
		ORDER BY d`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var day string
		var assets, vulns, tasks int64
		if err := rows.Scan(&day, &assets, &vulns, &tasks); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"date": day, "assets": assets, "vulnerabilities": vulns, "tasks": tasks,
		})
	}
	return out, rows.Err()
}

// RecentTasks 最近任务。
func (d *DashboardRepo) RecentTasks(ctx context.Context, limit int) ([]map[string]any, error) {
	rows, err := d.r.pool.Query(ctx, `
		SELECT id, name, status, coalesce(type,''), progress, created_at
		FROM tasks ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, status, typ string
		var progress int
		var at any
		if err := rows.Scan(&id, &name, &status, &typ, &progress, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "status": status, "type": typ,
			"progress": progress, "created_at": at,
		})
	}
	return out, rows.Err()
}

// RecentVulns 最近漏洞。
func (d *DashboardRepo) RecentVulns(ctx context.Context, limit int) ([]map[string]any, error) {
	rows, err := d.r.pool.Query(ctx, `
		SELECT id, name, severity, status, coalesce(target,''), created_at
		FROM vulnerabilities ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, severity, status, target string
		var at any
		if err := rows.Scan(&id, &name, &severity, &status, &target, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "severity": severity, "status": status,
			"target": target, "created_at": at,
		})
	}
	return out, rows.Err()
}

// RecentAssets 最近发现的站点（走新资产域的 sites 表）。
func (d *DashboardRepo) RecentAssets(ctx context.Context, limit int) ([]map[string]any, error) {
	rows, err := d.r.pool.Query(ctx, `
		SELECT s.id, s.value, s.http_status, coalesce(s.title,''), p.name, s.first_seen
		FROM sites s JOIN projects p ON p.id = s.project_id
		ORDER BY s.first_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var value, title, project string
		var status int
		var at any
		if err := rows.Scan(&id, &value, &status, &title, &project, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "value": value, "http_status": status, "title": title,
			"project_name": project, "first_seen": at,
		})
	}
	return out, rows.Err()
}

// Activities 取操作日志作为最近动态。
func (d *DashboardRepo) Activities(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	rows, err := d.r.pool.Query(ctx, `
		SELECT id, coalesce(username,''), coalesce(action,''), coalesce(module,''),
		       coalesce(target,''), created_at
		FROM operation_logs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var user, action, module, target string
		var at any
		if err := rows.Scan(&id, &user, &action, &module, &target, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "username": user, "action": action, "module": module,
			"target": target, "created_at": at,
		})
	}
	return out, rows.Err()
}
