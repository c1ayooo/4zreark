package repo

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Site 是归并后的资产（可访问站点），字段口径对齐 ScopesHub 实测结构。
type Site struct {
	ID                  int64      `json:"id"`
	ProjectID           int64      `json:"project_id"`
	ProjectCode         string     `json:"project_code"`
	ProjectName         string     `json:"project_name"`
	Host                string     `json:"host"`
	Port                int        `json:"port"`
	Protocol            string     `json:"protocol"`
	Value               string     `json:"value"`
	IP                  string     `json:"ip"`
	HTTPStatus          int        `json:"http_status"`
	Title               string     `json:"title"`
	IconSHA256          string     `json:"icon_sha256"`
	Tech                []string   `json:"technology_stack"`
	DiscoveryType       string     `json:"discovery_type"`
	State               string     `json:"state"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	RetryStep           int        `json:"retry_step"`
	CleanupEligible     bool       `json:"cleanup_eligible"`
	VerificationStatus  string     `json:"verification_status"`
	VerificationReason  string     `json:"verification_reason"`
	Attempts            int        `json:"attempts"`
	MaxAttempts         int        `json:"max_attempts"`
	FirstSeen           time.Time  `json:"first_seen"`
	LastSeen            time.Time  `json:"last_seen"`
	VerifiedAt          *time.Time `json:"verified_at"`
	NextVerificationAt  *time.Time `json:"next_verification_at"`
	// Endpoints 是站点的全部入口（协议 + 端口）。
	// 站点按 host 归并，所以 http:80 / https:443 / http:8080 都挂在这一个站点下，
	// 端口视图只能从这里读，sites.port 只是 https 优先的展示值。
	Endpoints []Endpoint `json:"endpoints"`
}

// Endpoint 是站点的入口（协议 + 端口）。
type Endpoint struct {
	Scheme     string `json:"scheme"`
	Port       int    `json:"port"`
	StatusCode int    `json:"status_code"`
}

// RawRecord 是一次采集得到的证据，只追加不覆盖业务状态。
type RawRecord struct {
	Source     string
	Host       string
	Port       int
	Protocol   string
	Value      string
	StatusCode int
	Title      string
	IP         string
	Evidence   map[string]any
}

// ImportResult 汇总一次导入。
type ImportResult struct {
	Records      int `json:"records"`
	NewSites     int `json:"new_sites"`
	DupRecords   int `json:"dup_records"`
	NewEndpoints int `json:"new_endpoints"`
}

// AssetRepo 是资产治理域的唯一数据入口。
type AssetRepo struct{ r *Repo }

func NewAssetRepo() *AssetRepo { return &AssetRepo{r: defaultRepo} }

const siteColumns = `s.id, s.project_id, p.code, p.name, s.host, s.port, s.protocol, s.value,
	coalesce(s.ip::text,''), s.http_status, coalesce(s.title,''), coalesce(s.icon_sha256,''),
	s.tech, s.discovery_type, s.state, s.consecutive_failures, s.retry_step, s.cleanup_eligible,
	s.verification_status, coalesce(s.verification_reason,''), s.attempts, s.max_attempts,
	s.first_seen, s.last_seen, s.verified_at, s.next_verification_at,
	coalesce((SELECT jsonb_agg(jsonb_build_object('scheme', e.scheme, 'port', e.port,
	                                             'status_code', e.status_code) ORDER BY e.port, e.scheme)
	            FROM site_endpoints e WHERE e.site_id = s.id), '[]'::jsonb)`

func scanSite(scan func(...any) error) (*Site, error) {
	var s Site
	var tech, eps []byte
	err := scan(&s.ID, &s.ProjectID, &s.ProjectCode, &s.ProjectName, &s.Host, &s.Port,
		&s.Protocol, &s.Value, &s.IP, &s.HTTPStatus, &s.Title, &s.IconSHA256, &tech,
		&s.DiscoveryType, &s.State, &s.ConsecutiveFailures, &s.RetryStep, &s.CleanupEligible,
		&s.VerificationStatus, &s.VerificationReason, &s.Attempts, &s.MaxAttempts,
		&s.FirstSeen, &s.LastSeen, &s.VerifiedAt, &s.NextVerificationAt, &eps)
	if err != nil {
		return nil, err
	}
	if len(tech) > 0 {
		_ = json.Unmarshal(tech, &s.Tech)
	}
	if s.Tech == nil {
		s.Tech = []string{}
	}
	if len(eps) > 0 {
		_ = json.Unmarshal(eps, &s.Endpoints)
	}
	if s.Endpoints == nil {
		s.Endpoints = []Endpoint{}
	}
	return &s, nil
}

// Project 是资产归属边界。
type Project struct {
	ID          int64     `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Region      string    `json:"region"`
	Description string    `json:"description"`
	HomepageURL string    `json:"homepage_url"`
	Color       string    `json:"color"`
	Paused      bool      `json:"collection_paused"`
	PauseReason string    `json:"collection_pause_reason"`
	CycleDays   int       `json:"cycle_interval_days"`
	SeedCount   int       `json:"seed_count"`
	AssetCount  int       `json:"asset_count"`
	RecordCount int       `json:"record_count"`
	LostCount   int       `json:"lost_count"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (a *AssetRepo) ListProjects(ctx context.Context) ([]*Project, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	rows, err := a.r.pool.Query(ctx, `
		SELECT p.id, p.code, p.name, p.region, coalesce(p.description,''), coalesce(p.homepage_url,''),
		       coalesce(p.color,''), p.collection_paused, coalesce(p.collection_pause_reason,''),
		       p.cycle_interval_days, p.updated_at,
		       (SELECT count(*) FROM sites s WHERE s.project_id = p.id),
		       (SELECT count(*) FROM raw_records r WHERE r.project_id = p.id),
		       (SELECT count(*) FROM sites s WHERE s.project_id = p.id AND s.state = 'lost')
		FROM projects p ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Region, &p.Description, &p.HomepageURL,
			&p.Color, &p.Paused, &p.PauseReason, &p.CycleDays, &p.UpdatedAt,
			&p.AssetCount, &p.RecordCount, &p.LostCount); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// Overview 是对外统计口径：原始记录与归并站点分开计。
type Overview struct {
	Projects      int64            `json:"projects"`
	Assets        int64            `json:"assets"`
	Domains       int64            `json:"domains"`
	Sites         int64            `json:"sites"`
	VerifiedSites int64            `json:"verified_sites"`
	Records       int64            `json:"record_count"`
	Lost          int64            `json:"lost_count"`
	NewToday      int64            `json:"new_today"`
	TopTech       []map[string]any `json:"technology_counts"`
	RecentEvents  []map[string]any `json:"recent_events"`
}

func (a *AssetRepo) Overview(ctx context.Context) (*Overview, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	o := &Overview{}
	// 一次扫描算完：原来 4 个独立子查询各扫一遍 sites，22 万资产时是 4 倍开销。
	// projects / raw_records 的精确计数仍需各扫一次（表小；量级上来再换 reltuples 估算）。
	err := a.r.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(DISTINCT host),
		       count(*) FILTER (WHERE state = 'reachable'),
		       count(*) FILTER (WHERE state = 'lost'),
		       count(*) FILTER (WHERE first_seen >= date_trunc('day', now())),
		       (SELECT count(*) FROM projects),
		       (SELECT count(*) FROM raw_records)
		  FROM sites`).
		Scan(&o.Sites, &o.Domains, &o.VerifiedSites, &o.Lost, &o.NewToday, &o.Projects, &o.Records)
	if err != nil {
		return nil, err
	}
	o.Assets = o.Sites

	rows, err := a.r.pool.Query(ctx, `
		SELECT t.key, count(*) FROM sites s, jsonb_array_elements_text(s.tech) AS t(key)
		WHERE s.tech <> '[]'::jsonb GROUP BY t.key ORDER BY count(*) DESC LIMIT 8`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int64
			if rows.Scan(&k, &n) == nil {
				o.TopTech = append(o.TopTech, map[string]any{"key": k, "name": k, "site_count": n})
			}
		}
	}
	if o.TopTech == nil {
		o.TopTech = []map[string]any{}
	}
	if o.RecentEvents, err = a.RecentEvents(ctx, 10); err != nil {
		o.RecentEvents = []map[string]any{}
	}
	return o, nil
}

func (a *AssetRepo) RecentEvents(ctx context.Context, limit int) ([]map[string]any, error) {
	rows, err := a.r.pool.Query(ctx, `
		SELECT e.id, e.event_type, e.title, s.value, p.name, e.created_at
		FROM asset_events e JOIN sites s ON s.id = e.site_id JOIN projects p ON p.id = e.project_id
		ORDER BY e.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var et, title, value, pname string
		var at time.Time
		if err := rows.Scan(&id, &et, &title, &value, &pname, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "event_type": et, "title": title,
			"asset_value": value, "project_name": pname, "created_at": at})
	}
	return out, rows.Err()
}

// ImportRecords 写入原始记录并归并到站点。
//
// 归并键 (project, host)：http/https 合并成一个站点，端口取 https 优先，入口明细留在 raw_records。
// 同一 dedup_key 再次出现时更新证据字段，保留变化以便后续生成属性变更事件。
func (a *AssetRepo) ImportRecords(ctx context.Context, projectID int64, source string, recs []RawRecord) (*ImportResult, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	res := &ImportResult{}
	tx, err := a.r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	for _, rec := range recs {
		host := normalizeHost(rec.Host)
		if host == "" {
			continue
		}
		proto := rec.Protocol
		if proto == "" {
			proto = "https"
		}
		port := rec.Port
		if port == 0 {
			if proto == "http" {
				port = 80
			} else {
				port = 443
			}
		}
		value := rec.Value
		if value == "" {
			value = fmt.Sprintf("%s://%s", proto, host)
			if (proto == "http" && port != 80) || (proto == "https" && port != 443) {
				value = fmt.Sprintf("%s://%s:%d", proto, host, port)
			}
		}
		key := siteKey(projectID, host)
		dedup := dedupKey(projectID, source, host, port, proto, value)

		var inserted bool
		err = tx.QueryRow(ctx, `
			INSERT INTO raw_records (project_id, source, host, port, protocol, value, status_code,
				title, ip, evidence, dedup_key, observed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,nullif($8,''),nullif($9,'')::inet,$10,$11,now())
			ON CONFLICT (dedup_key) DO UPDATE SET
				status_code = EXCLUDED.status_code,
				title = coalesce(EXCLUDED.title, raw_records.title),
				ip = coalesce(EXCLUDED.ip, raw_records.ip),
				evidence = EXCLUDED.evidence,
				observed_at = now()
			RETURNING (xmax = 0)`,
			projectID, source, host, port, proto, value, rec.StatusCode, rec.Title, rec.IP,
			toJSONB(rec.Evidence), dedup).Scan(&inserted)
		if err != nil {
			return nil, fmt.Errorf("写入原始记录失败: %w", err)
		}
		if inserted {
			res.Records++
		} else {
			res.DupRecords++
		}

		// 站点创建/更新：RETURNING (xmax = 0) 判定是否新建，RowsAffected 在 upsert 下恒为 1
		var siteID int64
		var siteInserted bool
		err = tx.QueryRow(ctx, `
			INSERT INTO sites (project_id, site_key, host, port, protocol, value, ip, http_status,
				title, state, verification_status, attempts, max_attempts, first_seen, last_seen, verified_at)
			VALUES ($1,$2,$3,$4,$5,$6,nullif($7,'')::inet,$8,nullif($9,''),
				'pending','pending',0,3,now(),now(),null)
			ON CONFLICT (site_key) DO UPDATE SET
				last_seen = now(),
				http_status = CASE WHEN EXCLUDED.http_status > 0 THEN EXCLUDED.http_status ELSE sites.http_status END,
				title = coalesce(EXCLUDED.title, sites.title),
				ip = coalesce(EXCLUDED.ip, sites.ip),
				protocol = CASE WHEN EXCLUDED.protocol = 'https' THEN 'https' ELSE sites.protocol END,
				value = CASE WHEN EXCLUDED.protocol = 'https' THEN EXCLUDED.value ELSE sites.value END,
				port = CASE WHEN EXCLUDED.protocol = 'https' THEN EXCLUDED.port ELSE sites.port END
			RETURNING id, (xmax = 0)`,
			projectID, key, host, port, proto, value, rec.IP, rec.StatusCode, rec.Title).Scan(&siteID, &siteInserted)
		if err != nil {
			return nil, fmt.Errorf("归并站点失败: %w", err)
		}
		if siteInserted {
			res.NewSites++
		}

		// 入口：站点按 host 归并，端口视图落在这里。
		// 同 host 的 http:80 与 http:8080 靠 (site_id, scheme, port) 区分，不会互相覆盖。
		var epInserted bool
		err = tx.QueryRow(ctx, `
			INSERT INTO site_endpoints (site_id, scheme, host, port, status_code)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (site_id, scheme, port) DO UPDATE SET
				status_code = CASE WHEN EXCLUDED.status_code > 0 THEN EXCLUDED.status_code
				                   ELSE site_endpoints.status_code END,
				last_seen_at = now()
			RETURNING (xmax = 0)`,
			siteID, proto, host, port, rec.StatusCode).Scan(&epInserted)
		if err != nil {
			return nil, fmt.Errorf("归并站点入口失败: %w", err)
		}
		if epInserted {
			res.NewEndpoints++
		}

		// 回填 raw_records.site_id，P4 的事件需要从证据反查站点
		if _, err := tx.Exec(ctx, `UPDATE raw_records SET site_id = $1 WHERE dedup_key = $2 AND site_id IS NULL`,
			siteID, dedup); err != nil {
			return nil, fmt.Errorf("回填站点关联失败: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// VerifySite 记录一次可达性判定，并按退避阶梯推进下一次检查时间。
func (a *AssetRepo) VerifySite(ctx context.Context, siteID int64, reachable bool, code int, reasonCode string) error {
	policy := struct {
		threshold int
		first     int
		second    int
		repeat    int
	}{3, 24, 72, 168}
	_ = a.r.pool.QueryRow(ctx, `SELECT failure_threshold, first_hours, second_hours, repeat_hours
		FROM connectivity_policies WHERE id = 1`).Scan(&policy.threshold, &policy.first, &policy.second, &policy.repeat)

	tx, err := a.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if reachable {
		_, err = tx.Exec(ctx, `
			UPDATE sites SET state='reachable', http_status=$2, consecutive_failures=0, retry_step=0,
				lost_since_ms=0, verified_at=now(), last_seen=now(),
				next_verification_at=now() + make_interval(hours => $3::int),
				verification_status='verified', verification_reason='http_ok', attempts=attempts+1
			WHERE id=$1`, siteID, code, policy.repeat)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE sites SET consecutive_failures=consecutive_failures+1,
				retry_step=retry_step+1, http_status=0, attempts=attempts+1,
				verification_status='failed', verification_reason=nullif($2,''),
				next_verification_at = now() + make_interval(hours => (CASE retry_step
					WHEN 0 THEN $3::int WHEN 1 THEN $4::int ELSE $5::int END)),
				state = CASE WHEN consecutive_failures+1 >= $6 THEN 'lost' ELSE state END,
				lost_since_ms = CASE WHEN consecutive_failures+1 >= $6 AND lost_since_ms = 0
					THEN (extract(epoch from now())*1000)::bigint ELSE lost_since_ms END
			WHERE id=$1`, siteID, reasonCode, policy.first, policy.second, policy.repeat, policy.threshold)
	}
	if err != nil {
		return err
	}
	status := "failed"
	if reachable {
		status = "verified"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO verifications (site_id, status, reason_code, http_status)
		VALUES ($1,$2,$3,$4)`, siteID, status, reasonCode, code); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AssetTargetsForDomain 取种子域下已归并站点的全部入口，作为周期回归的执行单元。
// 每个 (host, port) 一条：同 host 的 80 与 8080 是两个独立目标。
// 没有入口记录的站点（历史数据缺）按展示协议回落 80/443，保证不会漏站点。
func (r *Repo) AssetTargetsForDomain(ctx context.Context, projectID int64, domain string, limit int) ([]TargetInput, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("数据层未初始化")
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT s.host,
		       coalesce(e.port, CASE WHEN s.protocol = 'http' THEN 80 ELSE 443 END) AS port
		  FROM sites s
		  LEFT JOIN site_endpoints e ON e.site_id = s.id
		 WHERE s.project_id = $1
		   AND (s.host = $2 OR s.host LIKE '%.' || $2)
		 ORDER BY s.host, port
		 LIMIT $3`, projectID, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TargetInput{}
	for rows.Next() {
		var t TargetInput
		if err := rows.Scan(&t.Host, &t.Port); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AssetEndpoints 取一个站点的全部入口，供探测使用（含真实端口）。
func (a *AssetRepo) AssetEndpoints(ctx context.Context, siteID int64) ([]Endpoint, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	rows, err := a.r.pool.Query(ctx,
		`SELECT scheme, port, coalesce(status_code, 0)
		   FROM site_endpoints WHERE site_id = $1 ORDER BY port, scheme`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Endpoint{}
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.Scheme, &e.Port, &e.StatusCode); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SiteHost 取站点的主机名，探测时要用。
func (a *AssetRepo) SiteHost(ctx context.Context, siteID int64) (string, error) {
	if a == nil || a.r == nil {
		return "", fmt.Errorf("资产仓储未初始化")
	}
	var host string
	err := a.r.pool.QueryRow(ctx, `SELECT host FROM sites WHERE id = $1`, siteID).Scan(&host)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return host, err
}

// SiteIDByHost 按 (项目, host) 找站点。站点按 host 归并，所以这个组合唯一。
func (a *AssetRepo) SiteIDByHost(ctx context.Context, projectID int64, host string) (int64, error) {
	if a == nil || a.r == nil {
		return 0, fmt.Errorf("资产仓储未初始化")
	}
	var id int64
	err := a.r.pool.QueryRow(ctx,
		`SELECT id FROM sites WHERE project_id = $1 AND host = $2 LIMIT 1`, projectID, host).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// RecordInconclusive 记一次「判不出真假」的探测：只落流水、推下一次检查，不动失败计数。
// FakeIP、公网域名解析到私网这两种情况走这里——它们既不能证明站点活着，也不能证明站点没了。
func (a *AssetRepo) RecordInconclusive(ctx context.Context, siteID int64, reasonCode string) error {
	if a == nil || a.r == nil {
		return fmt.Errorf("资产仓储未初始化")
	}
	firstHours := 24
	_ = a.r.pool.QueryRow(ctx, `SELECT first_hours FROM connectivity_policies WHERE id = 1`).Scan(&firstHours)

	tx, err := a.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE sites SET attempts = attempts + 1,
		                 verification_status = 'pending',
		                 verification_reason = nullif($2, ''),
		                 next_verification_at = now() + make_interval(hours => $3)
		 WHERE id = $1`, siteID, reasonCode, firstHours); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO verifications (site_id, status, reason_code, attempts) VALUES ($1,'inconclusive',$2,1)`,
		siteID, reasonCode); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		h = strings.SplitN(strings.SplitN(h, "://", 2)[1], "/", 2)[0]
	}
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}

// siteKey 按 (project, host) 归并：http/https 合并成一个站点，端口作为入口明细保留在 raw_records。
func siteKey(projectID int64, host string) string {
	sum := sha1.Sum([]byte(fmt.Sprintf("%d|%s", projectID, host)))
	return hex.EncodeToString(sum[:])
}

func dedupKey(projectID int64, source, host string, port int, proto, value string) string {
	sum := sha1.Sum([]byte(fmt.Sprintf("%d|%s|%s|%d|%s|%s", projectID, source, host, port, proto, value)))
	return hex.EncodeToString(sum[:])
}

func toJSONB(m map[string]any) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}
