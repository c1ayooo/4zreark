package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/jackc/pgx/v5"
)

// POCFilter 是 POC 列表的查询条件。Enabled 为 nil 表示不按启停过滤。
type POCFilter struct {
	Type     string
	Severity string
	Tags     []string
	Enabled  *bool
	Keyword  string
	Page     int
	PageSize int
}

// POCStats 是 POC 的统计口径，等级与类型沿用固定枚举。
type POCStats struct {
	Total      int64
	Enabled    int64
	BySeverity map[string]int64
	ByType     map[string]int64
}

// PocRepo 是 POC 仓储入口，覆盖列表、单条、批量、导入与统计。
type PocRepo interface {
	Create(ctx context.Context, p *models.POC) error
	// Upsert 在 template_id 或 name 命中已有记录时覆盖，保留原 id 与创建时间。
	Upsert(ctx context.Context, p *models.POC) error
	GetByID(ctx context.Context, id string) (*models.POC, error)
	GetByName(ctx context.Context, name string) (*models.POC, error)
	GetByTemplateID(ctx context.Context, templateID string) (*models.POC, error)
	List(ctx context.Context, f POCFilter) ([]*models.POC, int64, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	Delete(ctx context.Context, id string) error
	BatchDelete(ctx context.Context, ids []string) (deleted, failed int)
	ClearAll(ctx context.Context) (int64, error)

	// ExistingKeys 批量判定哪些 template_id / name 已经存在，供导入去重使用。
	ExistingKeys(ctx context.Context, templateIDs, names []string) (map[string]bool, map[string]bool, error)
	// InsertBatch 批量写入，返回实际插入数与逐条失败原因。
	InsertBatch(ctx context.Context, pocs []*models.POC) (int, []string, error)
	Stats(ctx context.Context) (*POCStats, error)
}

type pocRepo struct{ r *Repo }

const pocColumns = `id, template_id, name, description, author, severity, type,
	tags, content, cve_id, refs, enabled, version, source, origin, intel_id,
	created_at, updated_at`

var pocUpdatable = map[string]string{
	"template_id": "template_id",
	"name":        "name",
	"description": "description",
	"author":      "author",
	"severity":    "severity",
	"type":        "type",
	"tags":        "tags",
	"content":     "content",
	"cve_id":      "cve_id",
	"references":  "refs",
	"refs":        "refs",
	"enabled":     "enabled",
	"version":     "version",
	"source":      "source",
	"origin":      "origin",
	"intel_id":    "intel_id",
}

var pocColumnConv = map[string]func(any) (any, error){
	"tags":     textArrayValue,
	"cve_id":   textArrayValue,
	"refs":     textArrayValue,
	"severity": stringValue,
	"origin":   stringValue,
	"enabled":  boolValue,
	"intel_id": intValue,
}

func scanPOC(row pgx.Row) (*models.POC, error) {
	var (
		p        models.POC
		hexID    string
		severity string
		intelID  *int64
		created  time.Time
		updated  time.Time
	)
	err := row.Scan(&hexID, &p.TemplateID, &p.Name, &p.Description, &p.Author, &severity, &p.Type,
		&p.Tags, &p.Content, &p.CVEID, &p.References, &p.Enabled, &p.Version, &p.Source,
		&p.Origin, &intelID, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var convErr error
	if p.ID, convErr = objectIDFromHex(hexID); convErr != nil {
		return nil, convErr
	}
	if intelID != nil {
		p.IntelID = *intelID
	}
	p.Severity = models.VulnSeverity(severity)
	p.CreatedAt = timeFromPG(&created)
	p.UpdatedAt = timeFromPG(&updated)
	return &p, nil
}

// pocArgs 把模型摊成与 pocColumns 对齐的参数，插入与覆盖共用。
func pocArgs(p *models.POC) []any {
	var intelID any
	if p.IntelID > 0 {
		intelID = p.IntelID
	}
	return []any{
		p.ID.Hex(), p.TemplateID, p.Name, p.Description, p.Author, string(p.Severity), p.Type,
		textArray(p.Tags), p.Content, textArray(p.CVEID), textArray(p.References),
		p.Enabled, p.Version, p.Source, p.Origin, intelID,
		p.CreatedAt.UTC(), p.UpdatedAt.UTC(),
	}
}

// pocUpdateArgs 只列 UPDATE 真正写入的列，避免出现未被引用的占位参数
// （PostgreSQL 无法推断未引用参数的类型，会报 42P18）。
func pocUpdateArgs(p *models.POC) []any {
	var intelID any
	if p.IntelID > 0 {
		intelID = p.IntelID
	}
	return []any{
		p.ID.Hex(), p.TemplateID, p.Name, p.Description, p.Author, string(p.Severity), p.Type,
		textArray(p.Tags), p.Content, textArray(p.CVEID), textArray(p.References),
		p.Enabled, p.Version, p.Source, p.Origin, intelID, p.UpdatedAt.UTC(),
	}
}

const pocInsertSQL = `insert into pocs (` + pocColumns + `)
	 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
	 on conflict do nothing`

func (r *pocRepo) Create(ctx context.Context, p *models.POC) error {
	normalizePOC(p)

	tag, err := r.r.pool.Exec(ctx, pocInsertSQL, pocArgs(p)...)
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// on conflict do nothing 命中已有 template_id
		return ErrDuplicate
	}
	return nil
}

func (r *pocRepo) Upsert(ctx context.Context, p *models.POC) error {
	normalizePOC(p)

	// 命中 template_id 或 name 时覆盖：保留原 id 与 created_at，只更新内容。
	var (
		existingID      string
		createdAt       time.Time
		existingEnabled bool
	)
	err := r.r.pool.QueryRow(ctx,
		`select id, created_at, enabled from pocs
		  where ($1 <> '' and template_id = $1) or ($2 <> '' and name = $2)
		  order by case when $1 <> '' and template_id = $1 then 0 else 1 end
		  limit 1`, p.TemplateID, p.Name).Scan(&existingID, &createdAt, &existingEnabled)
	switch {
	case err == nil:
		p.ID, err = objectIDFromHex(existingID)
		if err != nil {
			return err
		}
		p.CreatedAt = timeFromPG(&createdAt)
		p.UpdatedAt = time.Now()
		// 覆盖写不动启停：请求里没带 enabled 时是零值 false，
		// 直接落库会把「重新提交同一个 POC」变成「顺手停用它」。
		// 启停只能走 toggle 或显式带 true 的更新。
		if !p.Enabled {
			p.Enabled = existingEnabled
		}
		_, err = r.r.pool.Exec(ctx,
			`update pocs set template_id=$2, name=$3, description=$4, author=$5, severity=$6,
			        type=$7, tags=$8, content=$9, cve_id=$10, refs=$11, enabled=$12,
			        version=$13, source=$14, origin=$15, intel_id=$16, updated_at=$17
			  where id = $1`, pocUpdateArgs(p)...)
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	case errors.Is(err, pgx.ErrNoRows):
		// 新建默认启用：handler 直接绑定 models.POC，请求里没带 enabled 时是零值 false，
		// 旧实现在插入分支强制置 true，这里保持一致。
		p.Enabled = true
		tag, err := r.r.pool.Exec(ctx, pocInsertSQL, pocArgs(p)...)
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrDuplicate
		}
		return nil
	default:
		return err
	}
}

func normalizePOC(p *models.POC) {
	if p.ID.IsZero() {
		p.ID = oid.NewObjectID()
	}
	if p.Origin == "" {
		p.Origin = "manual"
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
}

func (r *pocRepo) GetByID(ctx context.Context, id string) (*models.POC, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanPOC(r.r.pool.QueryRow(ctx, `select `+pocColumns+` from pocs where id = $1`, id))
}

func (r *pocRepo) GetByName(ctx context.Context, name string) (*models.POC, error) {
	return scanPOC(r.r.pool.QueryRow(ctx, `select `+pocColumns+` from pocs where name = $1 limit 1`, name))
}

func (r *pocRepo) GetByTemplateID(ctx context.Context, templateID string) (*models.POC, error) {
	return scanPOC(r.r.pool.QueryRow(ctx, `select `+pocColumns+` from pocs where template_id = $1`, templateID))
}

// pocWhere 参数位置固定：$1 类型、$2 等级、$3 启停、$4 关键字、$5 关键字模式、$6 标签。
const pocWhere = `where ($1 = '' or type = $1)
                   and ($2 = '' or severity = $2)
                   and ($3::bool is null or enabled = $3)
                   and ($4 = '' or name ilike $5 or description ilike $5
                        or exists (select 1 from unnest(cve_id) c where c ilike $5))
                   and ($6::text[] = '{}' or tags @> $6::text[])`

func (r *pocRepo) List(ctx context.Context, f POCFilter) ([]*models.POC, int64, error) {
	page, pageSize := vulnPage(f.Page, f.PageSize)
	keyword := strings.TrimSpace(f.Keyword)
	args := []any{f.Type, f.Severity, f.Enabled, keyword, likePattern(keyword), textArray(f.Tags)}

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from pocs `+pocWhere, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+pocColumns+` from pocs `+pocWhere+` order by created_at desc, name limit $7 offset $8`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*models.POC
	for rows.Next() {
		p, err := scanPOC(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

func (r *pocRepo) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
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
		col, ok := pocUpdatable[k]
		if !ok {
			continue
		}
		val := v
		if conv, ok := pocColumnConv[col]; ok {
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
		"update pocs set "+strings.Join(sets, ", ")+fmt.Sprintf(" where id = $%d", i), args...)
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *pocRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from pocs where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *pocRepo) BatchDelete(ctx context.Context, ids []string) (int, int) {
	deleted, failed := 0, 0
	for _, id := range ids {
		if _, err := idFromString(id); err != nil {
			failed++
			continue
		}
		tag, err := r.r.pool.Exec(ctx, `delete from pocs where id = $1`, id)
		if err != nil || tag.RowsAffected() == 0 {
			failed++
			continue
		}
		deleted++
	}
	return deleted, failed
}

func (r *pocRepo) ClearAll(ctx context.Context) (int64, error) {
	tag, err := r.r.pool.Exec(ctx, `delete from pocs`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *pocRepo) ExistingKeys(ctx context.Context, templateIDs, names []string) (map[string]bool, map[string]bool, error) {
	byTemplate := make(map[string]bool, len(templateIDs))
	byName := make(map[string]bool, len(names))

	if len(templateIDs) > 0 {
		rows, err := r.r.pool.Query(ctx,
			`select template_id from pocs where template_id = any($1::text[])`, templateIDs)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var tid string
			if err := rows.Scan(&tid); err != nil {
				rows.Close()
				return nil, nil, err
			}
			byTemplate[tid] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	}

	if len(names) > 0 {
		rows, err := r.r.pool.Query(ctx, `select name from pocs where name = any($1::text[])`, names)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return nil, nil, err
			}
			byName[n] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	}

	return byTemplate, byName, nil
}

// InsertBatch 用一次事务内的批处理写入，单条冲突不拖累整批。
func (r *pocRepo) InsertBatch(ctx context.Context, pocs []*models.POC) (int, []string, error) {
	if len(pocs) == 0 {
		return 0, nil, nil
	}

	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback(ctx)

	const chunk = 500
	inserted := 0
	var errs []string

	for start := 0; start < len(pocs); start += chunk {
		end := start + chunk
		if end > len(pocs) {
			end = len(pocs)
		}
		batch := &pgx.Batch{}
		for _, p := range pocs[start:end] {
			normalizePOC(p)
			batch.Queue(pocInsertSQL, pocArgs(p)...)
		}
		results := tx.SendBatch(ctx, batch)
		for _, p := range pocs[start:end] {
			tag, err := results.Exec()
			switch {
			case err != nil:
				errs = append(errs, fmt.Sprintf("Failed to save %s: %v", p.Name, err))
			case tag.RowsAffected() == 0:
				errs = append(errs, fmt.Sprintf("Failed to save %s: 已存在", p.Name))
			default:
				inserted++
			}
		}
		if err := results.Close(); err != nil {
			return inserted, errs, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, nil, err
	}
	return inserted, errs, nil
}

func (r *pocRepo) Stats(ctx context.Context) (*POCStats, error) {
	var (
		total, enabled                    int64
		critical, high, medium, low, info int64
		nuclei, xray, custom              int64
	)
	err := r.r.pool.QueryRow(ctx,
		`select count(*),
		        count(*) filter (where enabled),
		        count(*) filter (where severity = 'critical'),
		        count(*) filter (where severity = 'high'),
		        count(*) filter (where severity = 'medium'),
		        count(*) filter (where severity = 'low'),
		        count(*) filter (where severity = 'info'),
		        count(*) filter (where type = 'nuclei'),
		        count(*) filter (where type = 'xray'),
		        count(*) filter (where type = 'custom')
		   from pocs`).Scan(&total, &enabled, &critical, &high, &medium, &low, &info,
		&nuclei, &xray, &custom)
	if err != nil {
		return nil, err
	}

	return &POCStats{
		Total:   total,
		Enabled: enabled,
		BySeverity: map[string]int64{
			"critical": critical, "high": high, "medium": medium, "low": low, "info": info,
		},
		ByType: map[string]int64{
			"nuclei": nuclei, "xray": xray, "custom": custom,
		},
	}, nil
}
