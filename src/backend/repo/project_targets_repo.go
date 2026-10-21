package repo

import (
	"context"
	"fmt"
)

// ProjectTargetValues 按目标类型读取项目整体结果里的监控目标原料：
//   - domain: 启用种子域名 + 站点主机 + 原始记录主机（由调用方归并根域）
//   - ip:     站点 IP + 原始记录 IP
//   - url:    站点入口 URL + 原始记录里的 HTTP(S) URL
//   - cidr:   启用种子 CIDR
//
// 只查询需要的维度，避免大项目每次巡航都扫四遍资产表。
func (a *AssetRepo) ProjectTargetValues(ctx context.Context, projectID int64, kind string) ([]string, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}

	var sql string
	switch kind {
	case "domain":
		sql = `
			SELECT DISTINCT v FROM (
				SELECT value AS v FROM seeds
				 WHERE project_id = $1 AND enabled AND kind = 'domain'
				UNION ALL
				SELECT host FROM sites WHERE project_id = $1
				UNION ALL
				SELECT host FROM raw_records WHERE project_id = $1
			) t
			 WHERE coalesce(btrim(v), '') <> ''
			 ORDER BY v`
	case "ip":
		sql = `
			SELECT DISTINCT v FROM (
				SELECT host(ip) AS v FROM sites WHERE project_id = $1 AND ip IS NOT NULL
				UNION ALL
				SELECT host(ip) FROM raw_records WHERE project_id = $1 AND ip IS NOT NULL
			) t
			 WHERE coalesce(btrim(v), '') <> ''
			 ORDER BY v`
	case "url":
		sql = `
			SELECT DISTINCT v FROM (
				SELECT value AS v FROM sites WHERE project_id = $1
				UNION ALL
				SELECT value FROM raw_records
				 WHERE project_id = $1 AND value ~* '^https?://'
			) t
			 WHERE coalesce(btrim(v), '') <> ''
			 ORDER BY v`
	case "cidr":
		sql = `
			SELECT DISTINCT btrim(value) AS v FROM seeds
			 WHERE project_id = $1 AND enabled AND kind = 'cidr'
			   AND coalesce(btrim(value), '') <> ''
			 ORDER BY v`
	default:
		return nil, fmt.Errorf("不支持的目标类型: %s", kind)
	}

	rows, err := a.r.pool.Query(ctx, sql, projectID)
	if err != nil {
		return nil, fmt.Errorf("读取项目监控目标失败: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
