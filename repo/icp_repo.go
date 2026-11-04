package repo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/net/idna"
)

// 工信部 ICP 查询任务与结果快照。

type ICPQuery struct {
	ID          string     `json:"id"`
	ProjectID   int64      `json:"project_id"`
	Query       string     `json:"query"`
	ServiceType int        `json:"service_type"`
	PageSize    int        `json:"page_size"`
	Status      string     `json:"status"`
	Total       int        `json:"total"`
	Pages       int        `json:"pages"`
	Fetched     int        `json:"fetched"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	// AutoPromote 查询完成后是否把备案域名自动转成 domain 种子。
	AutoPromote bool `json:"auto_promote"`
	// PromoteIntervalHours 转种子时同时建的计划周期（小时），0 表示只建种子。
	PromoteIntervalHours int `json:"promote_interval_hours"`
	// PromotedCount 本次查询最终新增的种子数（已存在的域名不计）。
	PromotedCount int `json:"promoted_count"`
}

type ICPFiling struct {
	ID               int64     `json:"id"`
	QueryID          string    `json:"query_id"`
	ProjectID        int64     `json:"project_id"`
	Domain           string    `json:"domain"`
	MainLicence      string    `json:"main_licence"`
	ServiceLicence   string    `json:"service_licence"`
	UnitName         string    `json:"unit_name"`
	NatureName       string    `json:"nature_name"`
	ContentType      string    `json:"content_type"`
	LeaderName       string    `json:"leader_name"`
	UpdateRecordTime string    `json:"update_record_time"`
	CreatedAt        time.Time `json:"created_at"`
}

type ICPFilingInput struct {
	Domain           string
	MainLicence      string
	ServiceLicence   string
	UnitName         string
	NatureName       string
	ContentType      string
	LeaderName       string
	UpdateRecordTime string
}

func (r *Repo) CreateICPQuery(ctx context.Context, projectID int64, query string, serviceType, pageSize int, autoPromote bool, promoteIntervalHours int) (*ICPQuery, error) {
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	if serviceType <= 0 {
		serviceType = 1
	}
	if pageSize <= 0 || pageSize > 40 {
		pageSize = 40
	}
	if promoteIntervalHours < 0 || promoteIntervalHours > 720 {
		return nil, errors.New("promote_interval_hours 需在 0..720")
	}
	if autoPromote && promoteIntervalHours == 0 {
		promoteIntervalHours = 24
	}
	q := &ICPQuery{
		ID: oid.NewObjectID().Hex(), ProjectID: projectID, Query: query,
		ServiceType: serviceType, PageSize: pageSize, Status: "queued",
		CreatedAt: time.Now().UTC(), AutoPromote: autoPromote,
		PromoteIntervalHours: promoteIntervalHours,
	}
	if _, err := r.pool.Exec(ctx, `
insert into icp_queries (id, project_id, query, service_type, page_size, status, created_at,
                         auto_promote, promote_interval_hours)
values ($1,$2,$3,$4,$5,'queued',$6,$7,$8)`,
		q.ID, q.ProjectID, q.Query, q.ServiceType, q.PageSize, q.CreatedAt,
		q.AutoPromote, q.PromoteIntervalHours); err != nil {
		return nil, err
	}
	return q, nil
}

func (r *Repo) MarkICPQueryRunning(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx,
		`update icp_queries set status='running', started_at=now() where id=$1 and status='queued'`, id)
	return err
}

func (r *Repo) UpdateICPQueryProgress(ctx context.Context, id string, total, pages, fetched int) error {
	_, err := r.pool.Exec(ctx,
		`update icp_queries set total=$2, pages=$3, fetched=$4 where id=$1`,
		id, total, pages, fetched)
	return err
}

func (r *Repo) FinishICPQuery(ctx context.Context, id, status, errMsg string) error {
	_, err := r.pool.Exec(ctx,
		`update icp_queries set status=$2, error=$3, finished_at=now() where id=$1`,
		id, status, errMsg)
	return err
}

func (r *Repo) GetICPQuery(ctx context.Context, id string) (*ICPQuery, error) {
	row := r.pool.QueryRow(ctx, `
select id, project_id, query, service_type, page_size, status, total, pages, fetched,
       error, created_at, started_at, finished_at,
       auto_promote, promote_interval_hours, promoted_count
  from icp_queries where id=$1`, id)
	q, err := scanICPQuery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return q, err
}

func (r *Repo) ListICPQueries(ctx context.Context, projectID int64, limit int) ([]*ICPQuery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `select id, project_id, query, service_type, page_size, status, total, pages, fetched,
	             error, created_at, started_at, finished_at,
	             auto_promote, promote_interval_hours, promoted_count
	        from icp_queries`
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		q += ` where project_id=$1`
	}
	args = append(args, limit)
	q += fmt.Sprintf(` order by created_at desc limit $%d`, len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ICPQuery{}
	for rows.Next() {
		item, err := scanICPQuery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanICPQuery(row interface{ Scan(...any) error }) (*ICPQuery, error) {
	var q ICPQuery
	if err := row.Scan(&q.ID, &q.ProjectID, &q.Query, &q.ServiceType, &q.PageSize, &q.Status,
		&q.Total, &q.Pages, &q.Fetched, &q.Error, &q.CreatedAt, &q.StartedAt, &q.FinishedAt,
		&q.AutoPromote, &q.PromoteIntervalHours, &q.PromotedCount); err != nil {
		return nil, err
	}
	q.CreatedAt = timeFromPG(&q.CreatedAt)
	return &q, nil
}

// InsertICPFilings 批量写快照；同一查询内同 (service_licence,domain) 去重。
func (r *Repo) InsertICPFilings(ctx context.Context, queryID string, projectID int64, items []ICPFilingInput) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	inserted := 0
	for _, it := range items {
		tag, err := r.pool.Exec(ctx, `
insert into icp_filings (query_id, project_id, domain, main_licence, service_licence,
                         unit_name, nature_name, content_type, leader_name, update_record_time)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
on conflict (query_id, service_licence, domain) do nothing`,
			queryID, projectID, it.Domain, it.MainLicence, it.ServiceLicence,
			it.UnitName, it.NatureName, it.ContentType, it.LeaderName, it.UpdateRecordTime)
		if err != nil {
			return inserted, err
		}
		inserted += int(tag.RowsAffected())
	}
	return inserted, nil
}

func (r *Repo) ListICPFilings(ctx context.Context, queryID string, limit int) ([]*ICPFiling, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
select id, query_id, project_id, domain, main_licence, service_licence, unit_name,
       nature_name, content_type, leader_name, update_record_time, created_at
  from icp_filings
 where query_id=$1
 order by id
 limit $2`, queryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ICPFiling{}
	for rows.Next() {
		var f ICPFiling
		if err := rows.Scan(&f.ID, &f.QueryID, &f.ProjectID, &f.Domain, &f.MainLicence,
			&f.ServiceLicence, &f.UnitName, &f.NatureName, &f.ContentType,
			&f.LeaderName, &f.UpdateRecordTime, &f.CreatedAt); err != nil {
			return nil, err
		}
		f.CreatedAt = timeFromPG(&f.CreatedAt)
		out = append(out, &f)
	}
	return out, rows.Err()
}

// ICPPromoteResult 是一次「备案结果转资产种子」的结果统计。
type ICPPromoteResult struct {
	Domains  int `json:"domains"`  // 备案里去重后、可扫描的域名数（已转 ASCII）
	Created  int `json:"created"`  // 本次新增的种子数
	Existing int `json:"existing"` // 项目里已存在、跳过的域名数
	Planned  int `json:"planned"`  // 同时新建的监控计划数
	Skipped  int `json:"skipped"`  // 无法归一到 ASCII 域名、被跳过的条数
}

// PromoteICPFilings 把一次 ICP 查询快照里的域名回灌成 domain 种子。
//
// 这是 icp_filings 唯一的消费方：在此之前该表只写不读，工信部查到的几十个
// 备案域名停在快照里，不会变成种子、不进监控计划、不探活，整条链路断在
// 「公司名 → 域名」之后。幂等：靠 seeds(project_id,kind,value) 唯一约束去重，
// 同一次查询重复调用不会产生重复种子或重复计划。
//
// intervalHours > 0 时给新建的种子补一条 next_run_at=now() 的计划，
// 这样 CycleService 的下一次 tick（60s）就会起批次，无需人工再点一次。
func (r *Repo) PromoteICPFilings(ctx context.Context, queryID string, projectID int64, intervalHours int) (*ICPPromoteResult, error) {
	if queryID == "" || projectID <= 0 {
		return nil, errors.New("query_id 与 project_id 必填")
	}
	if intervalHours < 0 || intervalHours > 720 {
		return nil, errors.New("interval_hours 需在 0..720")
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// 有效域名口径：与快照写入侧一致，另外必须能归一到 ASCII 域名。
	// 备案库里存在大量中文域名（mi.中国、小米科技有限责任公司.中国），原样写进
	// seeds 会让下游任务创建被目标校验整批拒绝，所以这里统一转 punycode。
	const validDomain = `btrim(domain) <> '' and domain !~ '\s'`

	raws, err := distinctICPDomains(ctx, tx, queryID, validDomain)
	if err != nil {
		return nil, err
	}
	values, skipped := normalizeICPDomains(raws)
	domains := len(values)

	ids := make([]int64, 0, len(values))
	if len(values) > 0 {
		rows, err := tx.Query(ctx, `
insert into seeds (project_id, kind, value)
select $1::bigint, 'domain', v
  from unnest($2::text[]) as v
on conflict (project_id, kind, value) do nothing
returning id`, projectID, values)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	planned := 0
	if intervalHours > 0 && len(ids) > 0 {
	planSQL := `
insert into monitoring_plans (seed_id, interval_hours, budget, trigger_mode, change_cooldown_minutes, enabled, next_run_at)
select s.id, $2, '{}'::jsonb, 'interval', 10, true, now()
  from seeds s
 where s.id = any($1)
   and not exists (select 1 from monitoring_plans p where p.seed_id = s.id)`
		tag, err := tx.Exec(ctx, planSQL, ids, intervalHours)
		if err != nil {
			return nil, err
		}
		planned = int(tag.RowsAffected())
	}

	if _, err := tx.Exec(ctx,
		`update icp_queries set promoted_count = promoted_count + $2 where id = $1`,
		queryID, len(ids)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	existing := domains - len(ids)
	if existing < 0 {
		existing = 0
	}
	return &ICPPromoteResult{
		Domains: domains, Created: len(ids), Existing: existing, Planned: planned,
		Skipped: skipped,
	}, nil
}

// distinctICPDomains 取一次查询里去重后的原始域名。
// validDomain 由调用方传入，保证「有效口径」只在一处定义。
func distinctICPDomains(ctx context.Context, tx pgx.Tx, queryID, validDomain string) ([]string, error) {
	rows, err := tx.Query(ctx, `
select distinct lower(btrim(domain)) from icp_filings
 where query_id = $1 and `+validDomain, queryID)
	if err != nil {
		return nil, err
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

// normalizeICPDomains 把备案域名归一成可扫描的 ASCII 域名并去重。
//
// 工信部快照里混着三类目标：正常 ASCII 域名、IDN 中文域名（mi.中国）、以及
// 只有中文后缀的占位名。IDN 走 idna 转 punycode（mi.中国 → mi.xn--fiqs8s），
// 转换后仍不像域名（含空白、非法标签、无点）的直接丢弃——这类目标进了 seeds
// 只会让下游任务创建整批判失败。
// 返回值 skipped 是丢弃条数，供调用方回写日志，避免"少了域名却没人知道"。
func normalizeICPDomains(raws []string) (values []string, skipped int) {
	seen := make(map[string]struct{}, len(raws))
	values = make([]string, 0, len(raws))
	for _, raw := range raws {
		v := normalizeICPDomain(raw)
		if v == "" {
			skipped++
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	return values, skipped
}

// normalizeICPDomain 单个备案域名的归一：去 scheme/path/端口/尾点 → punycode。
// 无法归一或形态明显不是域名时返回空串。
func normalizeICPDomain(raw string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	v = strings.TrimSuffix(v, ".")
	if host, _, err := net.SplitHostPort(v); err == nil {
		v = host
	}
	if net.ParseIP(v) != nil {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(v)
	if err != nil {
		return ""
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if !isASCIIHostname(ascii) {
		return ""
	}
	return ascii
}

// isASCIIHostname 校验转换后的主机名形态：至少两段、每段 1..63、首尾非连字符。
func isASCIIHostname(v string) bool {
	if len(v) == 0 || len(v) > 253 {
		return false
	}
	labels := strings.Split(v, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
