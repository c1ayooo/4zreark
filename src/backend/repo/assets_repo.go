package repo

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	// ResourceType 固定为 site，方便前端统一渲染 29 字段里的类型列。
	ResourceType string `json:"resource_type"`
	// LastHTTPVerifiedAt 是「最近一次 HTTP 探测确认」的时间，语义比 verified_at 更窄。
	LastHTTPVerifiedAt *time.Time `json:"last_http_verified_at"`
	// ICP 是从页面正文提取的工信部备案/许可证号（多号逗号分隔），
	// 存活验证探测时提取；icp_seen_at 记录最近一次提取时间。
	Icp       string     `json:"icp,omitempty"`
	IcpSeenAt *time.Time `json:"icp_seen_at,omitempty"`
	// 治理四件套：星标 / 标签 / 备注 / 忽略（人工运营字段，扫描流程不碰）。
	// 忽略的资产默认从所有列表视图与拓扑图隐藏，只有 view=ignored 可见。
	Starred bool     `json:"starred"`
	Tags    []string `json:"tags"`
	Note    string   `json:"note"`
	Ignored bool     `json:"ignored"`
	// CertNotAfter 是站点当前证书的到期时间（指纹扫描顺带采集），
	// 证书到期检测循环用它发提醒；未采集过为 nil。
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
	// Endpoints 是站点的全部入口（协议 + 端口）。
	// 站点按 host 归并，所以 http:80 / https:443 / http:8080 都挂在这一个站点下，
	// 端口视图只能从这里读，sites.port 只是 https 优先的展示值。
	Endpoints []Endpoint `json:"endpoints"`
	// RiskScore / Priority 是读时按观测证据实时算出的优先级（0-100 / p0-p4），
	// 不落库：评分输入里有漏洞等级这类会独立变化的字段，落库就必须做失效重算。
	RiskScore int    `json:"risk_score"`
	Priority  string `json:"priority"`
	// RiskFactors 是评分因子明细（为什么是 P2），与 RiskScore 同时计算。
	RiskFactors []RiskFactor `json:"risk_factors,omitempty"`
	// 列表页需要的聚合计数，避免前端为每个站点再发一次详情请求。
	EndpointCount    int        `json:"endpoint_count"`
	RecordCount      int        `json:"record_count"`
	FingerprintCount int        `json:"fingerprint_count"`
	LastRecordAt     *time.Time `json:"last_record_at,omitempty"`
	// RecentRecords 是该站点最近几条采集证据，供列表行内展开；
	// 只在带 with_recent 参数时查询，避免给 381 行各带一条子查询拖慢列表。
	RecentRecords []*AssetRecord `json:"recent_records,omitempty"`
}

// RiskFactor 是一条评分因子：加分/减分的来源与原因。
type RiskFactor struct {
	Factor string `json:"factor"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

// Endpoint 是站点的入口（协议 + 端口）。
type Endpoint struct {
	Scheme     string `json:"scheme"`
	Port       int    `json:"port"`
	StatusCode int    `json:"status_code"`
}

// RawRecord 是一次采集得到的证据，只追加不覆盖业务状态。
// Tech/Server/Icon 是扫描阶段顺手拿到的富化字段：指纹写 sites.tech，
// 图标按 sha256 去重进 asset_icons，站点只存引用。
type RawRecord struct {
	Source          string         `json:"source"`
	Host            string         `json:"host"`
	Port            int            `json:"port"`
	Protocol        string         `json:"protocol"`
	Value           string         `json:"value"`
	StatusCode      int            `json:"status_code"`
	Title           string         `json:"title"`
	IP              string         `json:"ip"`
	Tech            []string       `json:"tech,omitempty"`
	Server          string         `json:"server,omitempty"`
	BodyHash        string         `json:"body_hash,omitempty"`
	CertOrg         string         `json:"cert_org,omitempty"`
	CertNotAfter    time.Time      `json:"cert_not_after,omitempty"`
	CookieNames     []string       `json:"cookie_names,omitempty"`
	JSFrameworks    []string       `json:"js_frameworks,omitempty"`
	APIHosts        []string       `json:"api_hosts,omitempty"`
	IconSHA256      string         `json:"icon_sha256,omitempty"`
	IconMMH3        int64          `json:"icon_mmh3,omitempty"`
	IconContentType string         `json:"icon_content_type,omitempty"`
	IconData        []byte         `json:"-"`
	Evidence        map[string]any `json:"evidence,omitempty"`
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
	s.first_seen, s.last_seen, s.verified_at, s.next_verification_at, s.last_http_verified_at,
	s.icp, s.icp_seen_at,
	s.starred, coalesce(s.tags, '[]'::jsonb), coalesce(s.note, ''), s.ignored, s.cert_not_after,
	coalesce((SELECT jsonb_agg(jsonb_build_object('scheme', e.scheme, 'port', e.port,
	                                             'status_code', e.status_code) ORDER BY e.port, e.scheme)
	            FROM site_endpoints e WHERE e.site_id = s.id), '[]'::jsonb),
	(SELECT count(*) FROM site_endpoints e WHERE e.site_id = s.id),
	(SELECT count(*) FROM raw_records rr WHERE rr.site_id = s.id),
	(SELECT count(*) FROM fingerprint_hits fh WHERE fh.site_id = s.id),
	(SELECT max(rr.observed_at) FROM raw_records rr WHERE rr.site_id = s.id)`

func scanSite(scan func(...any) error) (*Site, error) {
	var s Site
	var tech, eps, tags []byte
	err := scan(&s.ID, &s.ProjectID, &s.ProjectCode, &s.ProjectName, &s.Host, &s.Port,
		&s.Protocol, &s.Value, &s.IP, &s.HTTPStatus, &s.Title, &s.IconSHA256, &tech,
		&s.DiscoveryType, &s.State, &s.ConsecutiveFailures, &s.RetryStep, &s.CleanupEligible,
		&s.VerificationStatus, &s.VerificationReason, &s.Attempts, &s.MaxAttempts,
		&s.FirstSeen, &s.LastSeen, &s.VerifiedAt, &s.NextVerificationAt, &s.LastHTTPVerifiedAt,
		&s.Icp, &s.IcpSeenAt,
		&s.Starred, &tags, &s.Note, &s.Ignored, &s.CertNotAfter, &eps,
		&s.EndpointCount, &s.RecordCount, &s.FingerprintCount, &s.LastRecordAt)
	if err != nil {
		return nil, err
	}
	s.ResourceType = "site"
	if len(tech) > 0 {
		_ = json.Unmarshal(tech, &s.Tech)
	}
	if s.Tech == nil {
		s.Tech = []string{}
	}
	if len(tags) > 0 {
		_ = json.Unmarshal(tags, &s.Tags)
	}
	if s.Tags == nil {
		s.Tags = []string{}
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
	IconSHA256  string    `json:"icon_sha256"`
	Paused      bool      `json:"collection_paused"`
	PauseReason string    `json:"collection_pause_reason"`
	CycleDays   int       `json:"cycle_interval_days"`
	SeedCount   int       `json:"seed_count"`
	AssetCount  int       `json:"asset_count"`
	RecordCount int       `json:"record_count"`
	LostCount   int       `json:"lost_count"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ProjectInput 是新建/编辑项目时可写的字段；code 只在新建时生效。
type ProjectInput struct {
	Code        string
	Name        string
	Region      string
	Description string
	HomepageURL string
	Color       string
	CycleDays   int
}

const projectColumns = `p.id, p.code, p.name, p.region, coalesce(p.description,''), coalesce(p.homepage_url,''),
	coalesce(p.color,''), coalesce(p.icon_sha256,''), p.collection_paused, coalesce(p.collection_pause_reason,''),
	p.cycle_interval_days, p.updated_at,
	(SELECT count(*) FROM sites s WHERE s.project_id = p.id),
	(SELECT count(*) FROM raw_records r WHERE r.project_id = p.id),
	(SELECT count(*) FROM sites s WHERE s.project_id = p.id AND s.state = 'lost'),
	(SELECT count(*) FROM seeds se WHERE se.project_id = p.id)`

func scanProject(row pgx.Row) (*Project, error) {
	var p Project
	if err := row.Scan(&p.ID, &p.Code, &p.Name, &p.Region, &p.Description, &p.HomepageURL,
		&p.Color, &p.IconSHA256, &p.Paused, &p.PauseReason, &p.CycleDays, &p.UpdatedAt,
		&p.AssetCount, &p.RecordCount, &p.LostCount, &p.SeedCount); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (a *AssetRepo) ListProjects(ctx context.Context) ([]*Project, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	rows, err := a.r.pool.Query(ctx, `SELECT `+projectColumns+` FROM projects p ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Project{}
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (a *AssetRepo) GetProject(ctx context.Context, id int64) (*Project, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	return scanProject(a.r.pool.QueryRow(ctx, `SELECT `+projectColumns+` FROM projects p WHERE p.id = $1`, id))
}

func (a *AssetRepo) CreateProject(ctx context.Context, in ProjectInput) (*Project, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	var id int64
	err := a.r.pool.QueryRow(ctx, `
		INSERT INTO projects (code, name, region, description, homepage_url, color, cycle_interval_days)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		in.Code, in.Name, in.Region, in.Description, in.HomepageURL, in.Color, in.CycleDays).Scan(&id)
	if isUniqueViolation(err) {
		return nil, fmt.Errorf("项目编码 %q 已存在", in.Code)
	}
	if err != nil {
		return nil, err
	}
	return a.GetProject(ctx, id)
}

func (a *AssetRepo) UpdateProject(ctx context.Context, id int64, in ProjectInput) (*Project, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	tag, err := a.r.pool.Exec(ctx, `
		UPDATE projects
		   SET name = $2, region = $3, description = $4, homepage_url = $5,
		       color = $6, cycle_interval_days = $7, updated_at = now()
		 WHERE id = $1`,
		id, in.Name, in.Region, in.Description, in.HomepageURL, in.Color, in.CycleDays)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return a.GetProject(ctx, id)
}

// SetProjectPaused 只改采集开关。到期的监控计划会在 DuePlans 里被项目开关拦住，
// 不级联改 monitoring_plans.enabled，恢复时能保留用户单独停用的计划。
func (a *AssetRepo) SetProjectPaused(ctx context.Context, id int64, paused bool, reason string) (*Project, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}
	tag, err := a.r.pool.Exec(ctx, `
		UPDATE projects
		   SET collection_paused = $2, collection_pause_reason = $3, updated_at = now()
		 WHERE id = $1`, id, paused, reason)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return a.GetProject(ctx, id)
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
	// SourceCounts 是原始记录按采集来源的分布（subdomain/httpx/crawler/手工导入…），
	// 支撑「按来源聚合」的概览口径；只取 Top8。
	SourceCounts []map[string]any `json:"source_counts"`
	RecentEvents []map[string]any `json:"recent_events"`
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
		-- 只统计能在指纹库里对上号的名称：sites.tech 里混着敏感信息抽取器写的
		-- 「电话号」「内网IP」这类非技术项，直接聚合会把它们排进技术栈 Top8。
		-- 同一产品被 dddd 与 wappalyzergo 各记一条（OpenResty / OpenResty-product），
		-- 去掉 -product 后缀并按站点去重，避免一个产品占两行。
		SELECT base, count(*) FROM (
			SELECT DISTINCT s.id, regexp_replace(t.key, '-product$', '', 'i') AS base
			FROM sites s, jsonb_array_elements_text(s.tech) AS t(key)
			JOIN fingerprint_rules r ON r.name = t.key AND r.enabled
		) x GROUP BY base ORDER BY count(*) DESC LIMIT 8`)
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
	// 来源分布：原始记录按 source 聚合，让「这些资产是谁发现的」一眼可见。
	srcRows, err := a.r.pool.Query(ctx, `
		SELECT source, count(*) AS cnt
		  FROM raw_records
		 GROUP BY source
		 ORDER BY cnt DESC
		 LIMIT 8`)
	if err == nil {
		defer srcRows.Close()
		for srcRows.Next() {
			var src string
			var n int64
			if srcRows.Scan(&src, &n) == nil {
				o.SourceCounts = append(o.SourceCounts, map[string]any{"source": src, "count": n})
			}
		}
	}
	if o.SourceCounts == nil {
		o.SourceCounts = []map[string]any{}
	}
	if o.RecentEvents, err = a.RecentEvents(ctx, 10); err != nil {
		o.RecentEvents = []map[string]any{}
	}
	return o, nil
}

func (a *AssetRepo) RecentEvents(ctx context.Context, limit int) ([]map[string]any, error) {
	return a.RecentEventsByProject(ctx, 0, limit)
}

// RecentEventsByProject 是事件时间线的项目收口版本；projectID=0 表示全部项目。
func (a *AssetRepo) RecentEventsByProject(ctx context.Context, projectID int64, limit int) ([]map[string]any, error) {
	rows, err := a.r.pool.Query(ctx, `
		SELECT e.id, e.project_id, e.site_id, e.record_id, e.event_type, e.title,
		       e.before, e.after, e.created_at, s.value, p.name
		FROM asset_events e
		JOIN sites s ON s.id = e.site_id
		JOIN projects p ON p.id = e.project_id
		WHERE ($2 = 0 OR e.project_id = $2)
		ORDER BY e.created_at DESC, e.id DESC LIMIT $1`, limit, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, projectID, siteID int64
		var recordID *int64
		var et, title, value, pname string
		var before, after []byte
		var at time.Time
		if err := rows.Scan(&id, &projectID, &siteID, &recordID, &et, &title,
			&before, &after, &at, &value, &pname); err != nil {
			return nil, err
		}
		var beforeMap, afterMap map[string]any
		_ = json.Unmarshal(before, &beforeMap)
		_ = json.Unmarshal(after, &afterMap)
		if beforeMap == nil {
			beforeMap = map[string]any{}
		}
		if afterMap == nil {
			afterMap = map[string]any{}
		}
		out = append(out, map[string]any{
			"id": id, "project_id": projectID, "site_id": siteID, "record_id": recordID,
			"event_type": et, "title": title, "before": beforeMap, "after": afterMap,
			"asset_value": value, "project_name": pname, "created_at": at,
		})
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

		var recordID int64
		var inserted bool
		err = tx.QueryRow(ctx, `
			INSERT INTO raw_records (project_id, source, host, port, protocol, value, status_code,
				title, ip, server, evidence, dedup_key, observed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,nullif($8,''),nullif($9,'')::inet,
			        $10,$11,$12,now())
			ON CONFLICT (dedup_key) DO UPDATE SET
				status_code = EXCLUDED.status_code,
				title = coalesce(EXCLUDED.title, raw_records.title),
				ip = coalesce(EXCLUDED.ip, raw_records.ip),
				server = CASE WHEN EXCLUDED.server <> '' THEN EXCLUDED.server ELSE raw_records.server END,
				evidence = EXCLUDED.evidence,
				observed_at = now()
			RETURNING id, (xmax = 0)`,
			projectID, source, host, port, proto, value, rec.StatusCode, rec.Title, rec.IP,
			rec.Server, toJSONB(rec.Evidence), dedup).Scan(&recordID, &inserted)
		if err != nil {
			return nil, fmt.Errorf("写入原始记录失败: %w", err)
		}
		if inserted {
			res.Records++
		} else {
			res.DupRecords++
		}

		// 事件用的旧站点快照（G5）：新建时无旧值，更新时做字段 diff。
		var oldTitle, oldIP string
		var oldStatus int
		oldFound := true
		err = tx.QueryRow(ctx,
			`SELECT coalesce(title, ''), http_status, coalesce(ip::text, '') FROM sites WHERE site_key = $1`,
			key).Scan(&oldTitle, &oldStatus, &oldIP)
		if errors.Is(err, pgx.ErrNoRows) {
			oldFound = false
			err = nil
		}
		if err != nil {
			return nil, fmt.Errorf("读取站点旧值失败: %w", err)
		}

		// 站点创建/更新：RETURNING (xmax = 0) 判定是否新建，RowsAffected 在 upsert 下恒为 1
		var siteID int64
		var siteInserted bool
		err = tx.QueryRow(ctx, `
			INSERT INTO sites (project_id, site_key, host, port, protocol, value, ip, http_status,
				title, body_hash, cert_org, cert_not_after, cookie_names, js_frameworks, api_hosts,
				state, verification_status, attempts, max_attempts, first_seen, last_seen, verified_at)
			VALUES ($1,$2,$3,$4,$5,$6,nullif($7,'')::inet,$8,nullif($9,''),nullif($10,''),
				nullif($11,''),$15,$12,$13,$14,
				'pending','pending',0,3,now(),now(),null)
			ON CONFLICT (site_key) DO UPDATE SET
				last_seen = now(),
				http_status = CASE WHEN EXCLUDED.http_status > 0 THEN EXCLUDED.http_status ELSE sites.http_status END,
				title = coalesce(EXCLUDED.title, sites.title),
				ip = coalesce(EXCLUDED.ip, sites.ip),
				protocol = CASE WHEN EXCLUDED.protocol = 'https' THEN 'https' ELSE sites.protocol END,
				body_hash = coalesce(EXCLUDED.body_hash, sites.body_hash),
				cert_org = coalesce(nullif(EXCLUDED.cert_org,''), sites.cert_org),
				cert_not_after = coalesce(EXCLUDED.cert_not_after, sites.cert_not_after),
				cookie_names = coalesce(EXCLUDED.cookie_names, sites.cookie_names),
				js_frameworks = coalesce(EXCLUDED.js_frameworks, sites.js_frameworks),
				api_hosts = coalesce(EXCLUDED.api_hosts, sites.api_hosts),
				value = CASE WHEN EXCLUDED.protocol = 'https' THEN EXCLUDED.value ELSE sites.value END,
				port = CASE WHEN EXCLUDED.protocol = 'https' THEN EXCLUDED.port ELSE sites.port END
			RETURNING id, (xmax = 0)`,
			projectID, key, host, port, proto, value, rec.IP, rec.StatusCode, rec.Title, rec.BodyHash,
			rec.CertOrg, stringSliceJSONB(rec.CookieNames), stringSliceJSONB(rec.JSFrameworks), stringSliceJSONB(rec.APIHosts),
			nullIfZeroTime(rec.CertNotAfter),
		).Scan(&siteID, &siteInserted)
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

		// 指纹/图标随扫描结果自动落到站点画像：技术栈进 sites.tech，
		// 图标字节按 sha256 去重进 asset_icons，站点只存引用。
		if len(rec.Tech) > 0 {
			if _, err := tx.Exec(ctx,
				`UPDATE sites SET tech = $2, tech_status = 'done' WHERE id = $1`,
				siteID, anyToJSONB(rec.Tech)); err != nil {
				return nil, fmt.Errorf("回写站点技术栈失败: %w", err)
			}
		}
		if rec.IconSHA256 != "" && len(rec.IconData) > 0 {
			ctype := rec.IconContentType
			if ctype == "" {
				ctype = "image/x-icon"
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO asset_icons (sha256, mmh3, content_type, size_bytes, data)
				VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT (sha256) DO NOTHING`,
				rec.IconSHA256, rec.IconMMH3, ctype, len(rec.IconData), rec.IconData); err != nil {
				return nil, fmt.Errorf("写入图标失败: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`UPDATE sites SET icon_sha256 = $2, icon_mmh3 = $3 WHERE id = $1`,
				siteID, rec.IconSHA256, rec.IconMMH3); err != nil {
				return nil, fmt.Errorf("回写站点图标失败: %w", err)
			}
		}

		// 回填 raw_records.site_id，P4 的事件需要从证据反查站点
		if _, err := tx.Exec(ctx, `UPDATE raw_records SET site_id = $1 WHERE dedup_key = $2 AND site_id IS NULL`,
			siteID, dedup); err != nil {
			return nil, fmt.Errorf("回填站点关联失败: %w", err)
		}

		// 事件（G5）：新站点 first_seen；已有站点做字段 diff。
		newTitle := rec.Title
		if newTitle == "" {
			newTitle = oldTitle
		}
		newStatus := rec.StatusCode
		if newStatus == 0 {
			newStatus = oldStatus
		}
		newIP := rec.IP
		if newIP == "" {
			newIP = oldIP
		}
		if siteInserted {
			if err := insertEventTx(ctx, tx, projectID, siteID, &recordID, "first_seen", "首次发现资产",
				map[string]any{}, map[string]any{
					"host": host, "ip": newIP, "title": newTitle, "http_status": newStatus,
				}); err != nil {
				return nil, fmt.Errorf("写入首次发现事件失败: %w", err)
			}
		} else if oldFound && (newTitle != oldTitle || newStatus != oldStatus || newIP != oldIP) {
			if err := insertEventTx(ctx, tx, projectID, siteID, &recordID, "attribute_change", "资产属性发生变化",
				map[string]any{"title": oldTitle, "http_status": oldStatus, "ip": oldIP},
				map[string]any{"title": newTitle, "http_status": newStatus, "ip": newIP}); err != nil {
				return nil, fmt.Errorf("写入属性变化事件失败: %w", err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// VerifySite 记录一次可达性判定，并按退避阶梯推进下一次检查时间。
// 失联判死（连续失败达阈值且此前不是 lost）时同事务落 down 事件，
// 事件时间线里的「宕机」由此而来；恢复侧的 reappear 在 VerifyService。
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

	// 失联判死需要知道旧状态与旧失败计数：此前 reachable/pending 才算「翻转为 lost」，
	// 已经是 lost 的继续失败不重复报事件。
	var prevState string
	var prevFailures int
	if !reachable {
		_ = tx.QueryRow(ctx, `SELECT state, consecutive_failures FROM sites WHERE id = $1`, siteID).
			Scan(&prevState, &prevFailures)
	}

	if reachable {
		_, err = tx.Exec(ctx, `
			UPDATE sites SET state='reachable', http_status=$2, consecutive_failures=0, retry_step=0,
				lost_since_ms=0, verified_at=now(), last_http_verified_at=now(), last_seen=now(),
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
	// 判死瞬间落 down 事件（带失败原因），项目与资产值从站点行补出；
	// 提交成功后触发 OnSiteDown 通知钩子（若已安装）。
	var downProjectID int64
	var downValue string
	if !reachable && prevState != "lost" && prevFailures+1 >= policy.threshold {
		if err := tx.QueryRow(ctx, `SELECT project_id, value FROM sites WHERE id = $1`, siteID).
			Scan(&downProjectID, &downValue); err == nil {
			if err := insertEventTx(ctx, tx, downProjectID, siteID, nil, "down", "资产失联",
				map[string]any{"state": prevState, "consecutive_failures": prevFailures},
				map[string]any{"state": "lost", "consecutive_failures": prevFailures + 1, "reason": reasonCode}); err != nil {
				return err
			}
		}
	}
	status := "failed"
	if reachable {
		status = "verified"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO verifications (site_id, status, reason_code, http_status)
		VALUES ($1,$2,$3,$4)`, siteID, status, reasonCode, code); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if downValue != "" && OnSiteDown != nil {
		OnSiteDown(downProjectID, siteID, downValue, reasonCode)
	}
	return nil
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
		  LEFT JOIN site_endpoints e ON e.site_id = s.id AND e.scheme IN ('http','https')
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
		t := TargetInput{Capability: map[string]any{"probe": true, "source": "site"}}
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
// SiteProjectID 返回站点所属项目；自动验证用它做 scope 校验。
func (a *AssetRepo) SiteProjectID(ctx context.Context, siteID int64) (int64, error) {
	var projectID int64
	err := a.r.pool.QueryRow(ctx, `SELECT project_id FROM sites WHERE id = $1`, siteID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return projectID, err
}

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

// TargetAllowedForProject 判断主机是否落在项目的站点或种子范围内。
// 绑定项目的 MCP key 用它限制直接扫描的目标；全项目 key 不走这里。
func (a *AssetRepo) TargetAllowedForProject(ctx context.Context, projectID int64, host string) (bool, error) {
	if a == nil || a.r == nil {
		return false, errUninitialized()
	}
	rawHost := strings.TrimSpace(host)
	if _, _, parseErr := net.ParseCIDR(rawHost); parseErr == nil {
		host = strings.ToLower(rawHost)
	} else {
		host = normalizeHost(host)
	}
	if host == "" {
		return false, nil
	}
	var ok bool
	err := a.r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sites s
			 WHERE s.project_id = $1
			   AND (lower(s.host) = $2 OR lower(coalesce(s.ip::text, '')) = $2)
			UNION ALL
			SELECT 1 FROM seeds se
			 WHERE se.project_id = $1 AND se.enabled
			   AND (
			       (se.kind = 'domain' AND (lower(se.value) = $2 OR $2 LIKE '%.' || lower(se.value)))
			       OR (se.kind IN ('app','company','repo','dict') AND lower(se.value) = $2)
			   )
		)`, projectID, host).Scan(&ok)
	if err != nil || ok {
		return ok, err
	}
	// CIDR 目标：允许落在任一 CIDR 种子内（含相等）。
	if _, _, parseErr := net.ParseCIDR(host); parseErr == nil {
		err = a.r.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM seeds
				 WHERE project_id = $1 AND enabled AND kind = 'cidr'
				   AND value::cidr >>= $2::cidr
			)`, projectID, host).Scan(&ok)
		return ok, err
	}
	// IP 目标再查一次 CIDR 种子；单独查询避免非 IP 字符串做 inet 转换时报错。
	if net.ParseIP(host) == nil {
		return false, nil
	}
	err = a.r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM seeds
			 WHERE project_id = $1 AND enabled AND kind = 'cidr'
			   AND $2::inet <<= value::cidr
		)`, projectID, host).Scan(&ok)
	return ok, err
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

// anyToJSONB 序列化任意值（含 []string），失败回落 "{}"。
// stringSliceJSONB 字符串切片转 jsonb：空切片返回 nil（SQL NULL），
// 让 upsert 的 coalesce 保住既有值，避免空覆盖。
func stringSliceJSONB(v []string) []byte {
	if len(v) == 0 {
		return nil
	}
	return anyToJSONB(v)
}

func anyToJSONB(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// nullIfZeroTime 零值时间转 SQL NULL，让 upsert 的 coalesce 保住既有证书到期时间。
func nullIfZeroTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
