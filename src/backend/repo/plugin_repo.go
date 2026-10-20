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

// PluginFilter 是插件列表的查询条件。
type PluginFilter struct {
	Type     string
	Language string
	Enabled  *bool
	Keyword  string
	Page     int
	PageSize int
}

// PluginRepo 是插件仓储入口。
type PluginRepo interface {
	Create(ctx context.Context, p *models.Plugin) error
	GetByID(ctx context.Context, id string) (*models.Plugin, error)
	GetByName(ctx context.Context, name string) (*models.Plugin, error)
	List(ctx context.Context, f PluginFilter) ([]*models.Plugin, int64, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	Delete(ctx context.Context, id string) error
}

// DictRepo 是字典仓储入口。
type DictRepo interface {
	Create(ctx context.Context, d *models.Dictionary) error
	GetByID(ctx context.Context, id string) (*models.Dictionary, error)
	List(ctx context.Context, dictType string, page, pageSize int) ([]*models.Dictionary, int64, error)
	Delete(ctx context.Context, id string) error
}

type pluginRepo struct{ r *Repo }

type dictRepo struct{ r *Repo }

const pluginColumns = `id, name, description, author, version, type, language, entry_file,
	config, dependencies, enabled, installed, source, downloads, rating, tags,
	created_at, updated_at`

var pluginUpdatable = map[string]string{
	"name":         "name",
	"description":  "description",
	"author":       "author",
	"version":      "version",
	"type":         "type",
	"language":     "language",
	"entry_file":   "entry_file",
	"config":       "config",
	"dependencies": "dependencies",
	"enabled":      "enabled",
	"installed":    "installed",
	"source":       "source",
	"downloads":    "downloads",
	"rating":       "rating",
	"tags":         "tags",
}

var pluginColumnConv = map[string]func(any) (any, error){
	"config":       pluginConfigValue,
	"dependencies": textArrayValue,
	"tags":         textArrayValue,
	"enabled":      boolValue,
	"installed":    boolValue,
}

// pluginConfigValue 把插件的 config 落成 jsonb。
func pluginConfigValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return []byte("{}"), nil
	case map[string]interface{}:
		b, err := json.Marshal(x)
		if err != nil {
			return nil, err
		}
		return b, nil
	default:
		return jsonb(v)
	}
}

func scanPlugin(row pgx.Row) (*models.Plugin, error) {
	var (
		p         models.Plugin
		hexID     string
		nodeType  string
		configB   []byte
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&hexID, &p.Name, &p.Description, &p.Author, &p.Version, &nodeType, &p.Language,
		&p.EntryFile, &configB, &p.Dependencies, &p.Enabled, &p.Installed, &p.Source,
		&p.Downloads, &p.Rating, &p.Tags, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if p.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	p.Type = nodeType
	if len(configB) > 0 {
		_ = json.Unmarshal(configB, &p.Config)
	}
	p.CreatedAt = timeFromPG(&createdAt)
	p.UpdatedAt = timeFromPG(&updatedAt)
	return &p, nil
}

func (r *pluginRepo) Create(ctx context.Context, p *models.Plugin) error {
	if p.ID.IsZero() {
		p.ID = oid.NewObjectID()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	cfg, err := pluginConfigValue(p.Config)
	if err != nil {
		return err
	}

	_, err = r.r.pool.Exec(ctx,
		`insert into plugins (`+pluginColumns+`)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		p.ID.Hex(), p.Name, p.Description, p.Author, p.Version, p.Type, p.Language,
		p.EntryFile, cfg, textArray(p.Dependencies), p.Enabled, p.Installed, p.Source,
		p.Downloads, p.Rating, textArray(p.Tags), p.CreatedAt.UTC(), p.UpdatedAt.UTC())
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

func (r *pluginRepo) GetByID(ctx context.Context, id string) (*models.Plugin, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanPlugin(r.r.pool.QueryRow(ctx, `select `+pluginColumns+` from plugins where id = $1`, id))
}

func (r *pluginRepo) GetByName(ctx context.Context, name string) (*models.Plugin, error) {
	return scanPlugin(r.r.pool.QueryRow(ctx, `select `+pluginColumns+` from plugins where name = $1`, name))
}

func (r *pluginRepo) List(ctx context.Context, f PluginFilter) ([]*models.Plugin, int64, error) {
	page, pageSize := vulnPage(f.Page, f.PageSize)
	keyword := strings.TrimSpace(f.Keyword)
	args := []any{f.Type, f.Language, f.Enabled, keyword, likePattern(keyword)}

	const where = `where ($1 = '' or type = $1)
	                 and ($2 = '' or language = $2)
	                 and ($3::bool is null or enabled = $3)
	                 and ($4 = '' or name ilike $5 or description ilike $5)`

	var total int64
	if err := r.r.pool.QueryRow(ctx, `select count(*) from plugins `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+pluginColumns+` from plugins `+where+` order by name limit $6 offset $7`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*models.Plugin
	for rows.Next() {
		p, err := scanPlugin(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

func (r *pluginRepo) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
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
		col, ok := pluginUpdatable[k]
		if !ok {
			continue
		}
		val := v
		if c, ok := pluginColumnConv[col]; ok {
			var err error
			if val, err = c(v); err != nil {
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
		"update plugins set "+strings.Join(sets, ", ")+fmt.Sprintf(" where id = $%d", i), args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *pluginRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from plugins where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- 字典

const dictColumns = `id, name, type, description, file_path, line_count, is_builtin,
	created_by, created_at, updated_at`

func scanDict(row pgx.Row) (*models.Dictionary, error) {
	var (
		d         models.Dictionary
		hexID     string
		createdBy *string
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&hexID, &d.Name, &d.Type, &d.Description, &d.FilePath, &d.LineCount,
		&d.IsBuiltin, &createdBy, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if d.ID, err = objectIDFromHex(hexID); err != nil {
		return nil, err
	}
	if createdBy != nil {
		if d.CreatedBy, err = objectIDFromHex(*createdBy); err != nil {
			return nil, err
		}
	}
	d.CreatedAt = timeFromPG(&createdAt)
	d.UpdatedAt = timeFromPG(&updatedAt)
	return &d, nil
}

func (r *dictRepo) Create(ctx context.Context, d *models.Dictionary) error {
	if d.ID.IsZero() {
		d.ID = oid.NewObjectID()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now()
	}
	if d.UpdatedAt.IsZero() {
		d.UpdatedAt = d.CreatedAt
	}

	_, err := r.r.pool.Exec(ctx,
		`insert into dictionaries (`+dictColumns+`) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		d.ID.Hex(), d.Name, d.Type, d.Description, d.FilePath, d.LineCount, d.IsBuiltin,
		objectIDOrNil(d.CreatedBy), d.CreatedAt.UTC(), d.UpdatedAt.UTC())
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

func (r *dictRepo) GetByID(ctx context.Context, id string) (*models.Dictionary, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanDict(r.r.pool.QueryRow(ctx, `select `+dictColumns+` from dictionaries where id = $1`, id))
}

func (r *dictRepo) List(ctx context.Context, dictType string, page, pageSize int) ([]*models.Dictionary, int64, error) {
	page, pageSize = vulnPage(page, pageSize)

	var total int64
	if err := r.r.pool.QueryRow(ctx,
		`select count(*) from dictionaries where ($1 = '' or type = $1)`, dictType).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx,
		`select `+dictColumns+` from dictionaries
		  where ($1 = '' or type = $1)
		  order by name limit $2 offset $3`, dictType, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*models.Dictionary
	for rows.Next() {
		d, err := scanDict(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

func (r *dictRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from dictionaries where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
