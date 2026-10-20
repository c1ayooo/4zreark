package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
)

// VulnFilter 是漏洞列表的查询条件，和原来 Mongo 的 filter 一一对应。
type VulnFilter struct {
	WorkspaceID string
	Severity    string
	Status      string
	Keyword     string
	TaskID      string
	Page        int
	PageSize    int
}

// VulnTrendRow 是趋势聚合的一行：某天某等级的数量。
type VulnTrendRow struct {
	Date     string
	Severity string
	Count    int64
}

// VulnRepo 是漏洞域仓储入口。POC 与报告原本就在 VulnService 上，
// 调用方不需要多拿一个依赖，所以一并放在这里。
type VulnRepo interface {
	Create(ctx context.Context, v *models.Vulnerability) error
	GetByID(ctx context.Context, id string) (*models.Vulnerability, error)
	List(ctx context.Context, f VulnFilter) ([]*models.Vulnerability, int64, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	Delete(ctx context.Context, id string) error
	BatchUpdateStatus(ctx context.Context, ids []string, status string) (int64, error)
	ListByTaskID(ctx context.Context, taskID string, page, pageSize int) ([]*models.Vulnerability, int64, error)

	// SeverityCounts 返回按等级的数量与总数，供报告摘要使用。
	SeverityCounts(ctx context.Context, workspaceID string) (map[string]int64, int64, error)
	// GroupCounts 一次查询同时返回按等级、状态、类型的分布。
	GroupCounts(ctx context.Context, workspaceID string) (sev, status, typ map[string]int64, total int64, err error)
	Recent(ctx context.Context, workspaceID string, limit int) ([]*models.Vulnerability, error)
	Trend(ctx context.Context, workspaceID string, days int) ([]VulnTrendRow, error)

	CreateReport(ctx context.Context, r *models.VulnReport) error
	GetReport(ctx context.Context, id string) (*models.VulnReport, error)
	ListReports(ctx context.Context, workspaceID string, page, pageSize int) ([]*models.VulnReport, int64, error)
	DeleteReport(ctx context.Context, id string) error
}

type vulnRepo struct{ r *Repo }

const vulnColumns = `id, workspace_id, asset_id, task_id,
	name, description, severity, status, type, template_id, target,
	method, payload, evidence, request, response,
	cve_id, cnnvd_id, refs, poc_id, poc_name,
	solution, fixed_at, fixed_by, last_verified_at,
	scanner, tags, created_at, updated_at`

// vulnUpdatable 是允许落库的列白名单。请求体里的键不可信，只认这张表。
var vulnUpdatable = map[string]string{
	"name":             "name",
	"description":      "description",
	"severity":         "severity",
	"status":           "status",
	"type":             "type",
	"template_id":      "template_id",
	"target":           "target",
	"method":           "method",
	"payload":          "payload",
	"evidence":         "evidence",
	"request":          "request",
	"response":         "response",
	"cve_id":           "cve_id",
	"cnnvd_id":         "cnnvd_id",
	"references":       "refs",
	"refs":             "refs",
	"poc_id":           "poc_id",
	"poc_name":         "poc_name",
	"solution":         "solution",
	"fixed_at":         "fixed_at",
	"fixed_by":         "fixed_by",
	"last_verified_at": "last_verified_at",
	"scanner":          "scanner",
	"tags":             "tags",
}

var vulnColumnConv = map[string]func(any) (any, error){
	"cve_id":           textArrayValue,
	"cnnvd_id":         textArrayValue,
	"refs":             textArrayValue,
	"tags":             textArrayValue,
	"severity":         stringValue,
	"status":           stringValue,
	"fixed_at":         timeValue,
	"last_verified_at": timeValue,
	"poc_id":           objectIDValue,
}

// vulnPage 归一化分页参数，上限与资产列表保持一致。
func vulnPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 20
	}
	return page, pageSize
}

func scanVuln(row pgx.Row) (*models.Vulnerability, error) {
	var (
		v          models.Vulnerability
		hexID      string
		wsID       string
		assetID    *string
		taskID     *string
		severity   string
		status     string
		pocID      *string
		fixedAt    *time.Time
		verifiedAt *time.Time
		createdAt  time.Time
		updatedAt  time.Time
	)

	err := row.Scan(&hexID, &wsID, &assetID, &taskID,
		&v.Name, &v.Description, &severity, &status, &v.Type, &v.TemplateID, &v.Target,
		&v.Method, &v.Payload, &v.Evidence, &v.Request, &v.Response,
		&v.CVEID, &v.CNNVDID, &v.References, &pocID, &v.POCName,
		&v.Solution, &fixedAt, &v.FixedBy, &verifiedAt,
		&v.Scanner, &v.Tags, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if v.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	if v.WorkspaceID, err = objectIDFromHex(wsID); err != nil {
		return nil, err
	}
	if assetID != nil {
		if v.AssetID, err = objectIDFromHex(*assetID); err != nil {
			return nil, err
		}
	}
	if taskID != nil {
		if v.TaskID, err = objectIDFromHex(*taskID); err != nil {
			return nil, err
		}
	}
	if pocID != nil {
		if v.POCID, err = objectIDFromHex(*pocID); err != nil {
			return nil, err
		}
	}
	v.Severity = models.VulnSeverity(severity)
	v.Status = models.VulnStatus(status)
	v.FixedAt = timeFromPG(fixedAt)
	v.LastVerifiedAt = timeFromPG(verifiedAt)
	v.CreatedAt = timeFromPG(&createdAt)
	v.UpdatedAt = timeFromPG(&updatedAt)
	return &v, nil
}

func (r *vulnRepo) Create(ctx context.Context, v *models.Vulnerability) error {
	if v.ID.IsZero() {
		v.ID = oid.NewObjectID()
	}
	if v.Status == "" {
		v.Status = models.VulnStatusNew
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = v.CreatedAt
	}

	_, err := r.r.pool.Exec(ctx,
		`insert into vulnerabilities (`+vulnColumns+`)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
		         $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)`,
		v.ID.Hex(), workspaceIDHex(v.WorkspaceID), objectIDOrNil(v.AssetID), objectIDOrNil(v.TaskID),
		v.Name, v.Description, string(v.Severity), string(v.Status), v.Type, v.TemplateID, v.Target,
		v.Method, v.Payload, v.Evidence, v.Request, v.Response,
		textArray(v.CVEID), textArray(v.CNNVDID), textArray(v.References), objectIDOrNil(v.POCID), v.POCName,
		v.Solution, timeToPG(v.FixedAt), v.FixedBy, timeToPG(v.LastVerifiedAt),
		v.Scanner, textArray(v.Tags), v.CreatedAt.UTC(), v.UpdatedAt.UTC())
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

func (r *vulnRepo) GetByID(ctx context.Context, id string) (*models.Vulnerability, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanVuln(r.r.pool.QueryRow(ctx, `select `+vulnColumns+` from vulnerabilities where id = $1`, id))
}

// vulnWhere 参数位置固定，避免关键字与分页参数串号。
const vulnWhere = `where ($1 = '' or workspace_id = $1)
                    and ($2 = '' or severity = $2)
                    and ($3 = '' or status = $3)
                    and ($4 = '' or task_id = $4)
                    and ($5 = '' or name ilike $6 or target ilike $6 or description ilike $6)`

// 等级按严重度排序，不按字典序：字典序会把 info 排到 medium 前面。
const vulnOrder = ` order by case severity
	                          when 'critical' then 0 when 'high' then 1 when 'medium' then 2
	                          when 'low' then 3 else 4 end,
	                        created_at desc`

func (r *vulnRepo) List(ctx context.Context, f VulnFilter) ([]*models.Vulnerability, int64, error) {
	page, pageSize := vulnPage(f.Page, f.PageSize)
	keyword := strings.TrimSpace(f.Keyword)
	args := []any{f.WorkspaceID, f.Severity, f.Status, f.TaskID, keyword, likePattern(keyword)}

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from vulnerabilities `+vulnWhere, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+vulnColumns+` from vulnerabilities `+vulnWhere+vulnOrder+` limit $7 offset $8`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*models.Vulnerability
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

func (r *vulnRepo) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	if len(fields) == 0 {
		return nil
	}

	sets := make([]string, 0, len(fields)+1)
	args := make([]any, 0, len(fields)+2)
	i := 1
	for k, v := range fields {
		col, ok := vulnUpdatable[k]
		if !ok {
			continue
		}
		val := v
		if conv, ok := vulnColumnConv[col]; ok {
			var err error
			if val, err = conv(v); err != nil {
				return fmt.Errorf("字段 %s 取值非法: %w", k, err)
			}
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", col, i))
		args = append(args, val)
		i++
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)

	tag, err := r.r.pool.Exec(ctx,
		"update vulnerabilities set "+strings.Join(sets, ", ")+fmt.Sprintf(" where id = $%d", i), args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *vulnRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from vulnerabilities where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *vulnRepo) BatchUpdateStatus(ctx context.Context, ids []string, status string) (int64, error) {
	clean := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := idFromString(id); err == nil {
			clean = append(clean, id)
		}
	}
	if len(clean) == 0 {
		return 0, ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx,
		`update vulnerabilities set status = $1, updated_at = now() where id = any($2::char(24)[])`,
		status, clean)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *vulnRepo) ListByTaskID(ctx context.Context, taskID string, page, pageSize int) ([]*models.Vulnerability, int64, error) {
	if _, err := idFromString(taskID); err != nil {
		return nil, 0, ErrNotFound
	}
	page, pageSize = vulnPage(page, pageSize)

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from vulnerabilities where task_id = $1`, taskID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+vulnColumns+` from vulnerabilities where task_id = $1`+vulnOrder+` limit $2 offset $3`,
		taskID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*models.Vulnerability
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

func (r *vulnRepo) SeverityCounts(ctx context.Context, workspaceID string) (map[string]int64, int64, error) {
	rows, err := r.r.pool.Query(ctx,
		`select severity, count(*) from vulnerabilities
		  where ($1 = '' or workspace_id = $1)
		  group by severity`, workspaceID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make(map[string]int64, 5)
	var total int64
	for rows.Next() {
		var (
			sev string
			n   int64
		)
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, 0, err
		}
		out[sev] = n
		total += n
	}
	return out, total, rows.Err()
}

func (r *vulnRepo) GroupCounts(ctx context.Context, workspaceID string) (map[string]int64, map[string]int64, map[string]int64, int64, error) {
	sev := make(map[string]int64)
	status := make(map[string]int64)
	typ := make(map[string]int64)

	// grouping sets 一次扫描拿到三个维度的分布，避免三次全表聚合。
	rows, err := r.r.pool.Query(ctx,
		`select severity, status, type, count(*)
		   from vulnerabilities
		  where ($1 = '' or workspace_id = $1)
		  group by grouping sets ((severity), (status), (type))`, workspaceID)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	defer rows.Close()

	var total int64
	for rows.Next() {
		var (
			s, st, t *string
			n        int64
		)
		if err := rows.Scan(&s, &st, &t, &n); err != nil {
			return nil, nil, nil, 0, err
		}
		switch {
		case s != nil:
			sev[*s] = n
			total += n
		case st != nil:
			status[*st] = n
		case t != nil:
			if *t != "" {
				typ[*t] = n
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, 0, err
	}
	return sev, status, typ, total, nil
}

func (r *vulnRepo) Recent(ctx context.Context, workspaceID string, limit int) ([]*models.Vulnerability, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := r.r.pool.Query(ctx,
		`select `+vulnColumns+` from vulnerabilities
		  where ($1 = '' or workspace_id = $1)
		  order by created_at desc limit $2`, workspaceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.Vulnerability
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *vulnRepo) Trend(ctx context.Context, workspaceID string, days int) ([]VulnTrendRow, error) {
	if days <= 0 {
		days = 30
	}
	rows, err := r.r.pool.Query(ctx,
		`select to_char(created_at at time zone 'Asia/Shanghai', 'YYYY-MM-DD') as d,
		        severity, count(*)
		   from vulnerabilities
		  where created_at >= (now() - ($2::int || ' days')::interval)
		    and ($1 = '' or workspace_id = $1)
		  group by 1, 2
		  order by 1`, workspaceID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []VulnTrendRow
	for rows.Next() {
		var row VulnTrendRow
		if err := rows.Scan(&row.Date, &row.Severity, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- 报告

const reportColumns = `id, workspace_id, name, type, summary, file_path, created_by, created_at`

func scanReport(row pgx.Row) (*models.VulnReport, error) {
	var (
		rep      models.VulnReport
		hexID    string
		wsID     string
		summary  []byte
		createdB *string
		created  time.Time
	)
	if err := row.Scan(&hexID, &wsID, &rep.Name, &rep.Type, &summary, &rep.FilePath, &createdB, &created); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if rep.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	if rep.WorkspaceID, err = objectIDFromHex(wsID); err != nil {
		return nil, err
	}
	if createdB != nil {
		if rep.CreatedBy, err = objectIDFromHex(*createdB); err != nil {
			return nil, err
		}
	}
	if len(summary) > 0 && string(summary) != "{}" {
		if err := json.Unmarshal(summary, &rep.Summary); err != nil {
			return nil, err
		}
	}
	rep.CreatedAt = timeFromPG(&created)
	return &rep, nil
}

func (r *vulnRepo) CreateReport(ctx context.Context, rep *models.VulnReport) error {
	if rep.ID.IsZero() {
		rep.ID = oid.NewObjectID()
	}
	if rep.CreatedAt.IsZero() {
		rep.CreatedAt = time.Now()
	}
	summary, err := jsonb(rep.Summary)
	if err != nil {
		return err
	}
	_, err = r.r.pool.Exec(ctx,
		`insert into vuln_reports (`+reportColumns+`) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		rep.ID.Hex(), workspaceIDHex(rep.WorkspaceID), rep.Name, rep.Type,
		summary, rep.FilePath, objectIDOrNil(rep.CreatedBy), rep.CreatedAt.UTC())
	return err
}

func (r *vulnRepo) GetReport(ctx context.Context, id string) (*models.VulnReport, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanReport(r.r.pool.QueryRow(ctx, `select `+reportColumns+` from vuln_reports where id = $1`, id))
}

func (r *vulnRepo) ListReports(ctx context.Context, workspaceID string, page, pageSize int) ([]*models.VulnReport, int64, error) {
	page, pageSize = vulnPage(page, pageSize)

	var total int64
	if err := r.r.pool.QueryRow(ctx,
		`select count(*) from vuln_reports where ($1 = '' or workspace_id = $1)`, workspaceID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+reportColumns+` from vuln_reports
		  where ($1 = '' or workspace_id = $1)
		  order by created_at desc limit $2 offset $3`,
		workspaceID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*models.VulnReport
	for rows.Next() {
		rep, err := scanReport(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rep)
	}
	return out, total, rows.Err()
}

func (r *vulnRepo) DeleteReport(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from vuln_reports where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
