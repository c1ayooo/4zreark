package repo

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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
	Records    int `json:"records"`
	NewSites   int `json:"new_sites"`
	DupRecords int `json:"dup_records"`
}

// AssetRepo 是资产治理域的唯一数据入口。
type AssetRepo struct{ r *Repo }

func NewAssetRepo() *AssetRepo { return &AssetRepo{r: defaultRepo} }

const siteColumns = `s.id, s.project_id, p.code, p.name, s.host, s.port, s.protocol, s.value,
	coalesce(s.ip::text,''), s.http_status, coalesce(s.title,''), coalesce(s.icon_sha256,''),
	s.tech, s.discovery_type, s.state, s.consecutive_failures, s.retry_step, s.cleanup_eligible,
	s.verification_status, coalesce(s.verification_reason,''), s.attempts, s.max_attempts,
	s.first_seen, s.last_seen, s.verified_at, s.next_verification_at`

func scanSite(scan func(...any) error) (*Site, error) {
	var s Site
	var tech []byte
	err := scan(&s.ID, &s.ProjectID, &s.ProjectCode, &s.ProjectName, &s.Host, &s.Port,
		&s.Protocol, &s.Value, &s.IP, &s.HTTPStatus, &s.Title, &s.IconSHA256, &tech,
		&s.DiscoveryType, &s.State, &s.ConsecutiveFailures, &s.RetryStep, &s.CleanupEligible,
		&s.VerificationStatus, &s.VerificationReason, &s.Attempts, &s.MaxAttempts,
		&s.FirstSeen, &s.LastSeen, &s.VerifiedAt, &s.NextVerificationAt)
	if err != nil {
		return nil, err
	}
	if len(tech) > 0 {
		_ = json.Unmarshal(tech, &s.Tech)
	}
	if s.Tech == nil {
		s.Tech = []string{}
	}
	return &s, nil
}

// ListSites 按 DSL 过滤分页返回站点。
func (a *AssetRepo) ListSites(ctx context.Context, projectID int64, q string, page, pageSize int) ([]*Site, int64, error) {
	if a == nil || a.r == nil {
		return nil, 0, fmt.Errorf("资产仓储未初始化")
	}
	where := []string{"1=1"}
	params := []any{}
	base := 1
	if projectID > 0 {
		params = append(params, projectID)
		where = append(where, fmt.Sprintf("s.project_id = $%d", len(params)))
		base = len(params) + 1
	}
	// DSL 编译时直接按起始偏移生成占位符，避免字符串替换在 $10 以上互相覆盖
	expr, dslArgs, err := BuildAssetWhereFrom(q, base)
	if err != nil {
		return nil, 0, err
	}
	if expr != "" {
		where = append(where, expr)
		params = append(params, dslArgs...)
	}
	cond := strings.Join(where, " AND ")

	var total int64
	countSQL := "SELECT count(*) FROM sites s JOIN projects p ON p.id = s.project_id WHERE " + cond
	if err := a.r.pool.QueryRow(ctx, countSQL, params...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计资产失败: %w", err)
	}

	offset := (page - 1) * pageSize
	params = append(params, pageSize, offset)
	sql := fmt.Sprintf(`SELECT %s FROM sites s JOIN projects p ON p.id = s.project_id
		WHERE %s ORDER BY s.first_seen DESC, s.id DESC LIMIT $%d OFFSET $%d`,
		siteColumns, cond, len(params)-1, len(params))

	rows, err := a.r.pool.Query(ctx, sql, params...)
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
	err := a.r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM projects),
		       (SELECT count(*) FROM sites),
		       (SELECT count(DISTINCT host) FROM sites),
		       (SELECT count(*) FROM sites WHERE state = 'reachable'),
		       (SELECT count(*) FROM raw_records),
		       (SELECT count(*) FROM sites WHERE state = 'lost'),
		       (SELECT count(*) FROM sites WHERE first_seen >= date_trunc('day', now()))`).
		Scan(&o.Projects, &o.Sites, &o.Domains, &o.VerifiedSites, &o.Records, &o.Lost, &o.NewToday)
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
