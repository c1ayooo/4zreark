package repo

import (
	"context"
	"time"
)

// AssetReportSummary 是信息收集报告需要的项目级聚合。
// 单独走 SQL 聚合而不是把站点全量拉到内存再算：报告统计必须对全量数据成立，
// 清单可以被模板截断，统计不能。
type AssetReportSummary struct {
	Sites      int64
	Reachable  int64
	Lost       int64
	Pending    int64
	Archived   int64
	NewWithin7 int64
	WithTech   int64
	WithIcon   int64
	Domains    int64
	IPs        int64
	Endpoints  int64
	Records    int64
	FirstSeen  *time.Time
	LastSeen   *time.Time

	ByState     []NameCount
	ByProto     []NameCount
	ByDiscovery []NameCount
	Ports       []PortCount
	Techs       []NameCount
}

type NameCount struct {
	Name  string
	Count int64
}

type PortCount struct {
	Scheme string
	Port   int
	Count  int64
}

// AssetReportSummary 汇总某项目的资产规模、状态与分布。
func (a *AssetRepo) AssetReportSummary(ctx context.Context, projectID int64) (*AssetReportSummary, error) {
	if a == nil || a.r == nil {
		return nil, errUninitialized()
	}
	s := &AssetReportSummary{}
	err := a.r.pool.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE state = 'reachable'),
       count(*) FILTER (WHERE state = 'lost'),
       count(*) FILTER (WHERE state NOT IN ('reachable','lost','archived')),
       count(*) FILTER (WHERE state = 'archived'),
       count(*) FILTER (WHERE first_seen >= now() - interval '7 days'),
       count(*) FILTER (WHERE jsonb_array_length(coalesce(tech,'[]'::jsonb)) > 0),
       count(*) FILTER (WHERE coalesce(icon_sha256,'') <> ''),
       count(DISTINCT host),
       count(DISTINCT ip),
       min(first_seen),
       max(last_seen)
  FROM sites WHERE project_id = $1`, projectID).
		Scan(&s.Sites, &s.Reachable, &s.Lost, &s.Pending, &s.Archived,
			&s.NewWithin7, &s.WithTech, &s.WithIcon, &s.Domains, &s.IPs,
			&s.FirstSeen, &s.LastSeen)
	if err != nil {
		return nil, err
	}

	// 原始记录按关联站点统计：sites.raw_count 是历史遗留列，并不总是维护。
	if err := a.r.pool.QueryRow(ctx, `
SELECT count(*) FROM raw_records r JOIN sites st ON st.id = r.site_id WHERE st.project_id = $1`,
		projectID).Scan(&s.Records); err != nil {
		return nil, err
	}

	if err := a.r.pool.QueryRow(ctx, `
SELECT count(*) FROM site_endpoints e JOIN sites st ON st.id = e.site_id WHERE st.project_id = $1`,
		projectID).Scan(&s.Endpoints); err != nil {
		return nil, err
	}

	if s.ByState, err = a.queryNameCounts(ctx, `
SELECT state, count(*) FROM sites WHERE project_id = $1 GROUP BY 1 ORDER BY 2 DESC, 1`, projectID); err != nil {
		return nil, err
	}
	if s.ByProto, err = a.queryNameCounts(ctx, `
SELECT protocol, count(*) FROM sites WHERE project_id = $1 GROUP BY 1 ORDER BY 2 DESC, 1`, projectID); err != nil {
		return nil, err
	}
	if s.ByDiscovery, err = a.queryNameCounts(ctx, `
SELECT discovery_type, count(*) FROM sites WHERE project_id = $1 GROUP BY 1 ORDER BY 2 DESC, 1`, projectID); err != nil {
		return nil, err
	}
	if s.Techs, err = a.queryNameCounts(ctx, `
SELECT t.value #>> '{}', count(*)
  FROM sites st, jsonb_array_elements(coalesce(st.tech,'[]'::jsonb)) t
 WHERE st.project_id = $1
 GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 30`, projectID); err != nil {
		return nil, err
	}

	rows, err := a.r.pool.Query(ctx, `
SELECT e.scheme, e.port, count(*)
  FROM site_endpoints e JOIN sites st ON st.id = e.site_id
 WHERE st.project_id = $1
 GROUP BY 1,2 ORDER BY 3 DESC, 1, 2 LIMIT 25`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pc PortCount
		if err := rows.Scan(&pc.Scheme, &pc.Port, &pc.Count); err != nil {
			return nil, err
		}
		s.Ports = append(s.Ports, pc)
	}
	return s, rows.Err()
}

func (a *AssetRepo) queryNameCounts(ctx context.Context, sql string, args ...any) ([]NameCount, error) {
	rows, err := a.r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NameCount
	for rows.Next() {
		var nc NameCount
		if err := rows.Scan(&nc.Name, &nc.Count); err != nil {
			return nil, err
		}
		out = append(out, nc)
	}
	return out, rows.Err()
}
