package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// APIKey 是外部平台 / MCP 的只读访问凭证。
// 库内只存哈希，明文只在创建响应里返回一次；ProjectID 为空表示可以读所有项目。
type APIKey struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	KeyPrefix    string     `json:"key_prefix"`
	ProjectID    *int64     `json:"project_id"`
	ProjectCode  string     `json:"project_code"`
	ProjectName  string     `json:"project_name"`
	Scopes       []string   `json:"scopes"`
	Enabled      bool       `json:"enabled"`
	ExpiresAt    *time.Time `json:"expires_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	RequestCount int64      `json:"request_count"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AllowsProject 判断这把 key 能否读某个项目。
func (k *APIKey) AllowsProject(projectID int64) bool {
	if k == nil {
		return false
	}
	return k.ProjectID == nil || *k.ProjectID == projectID
}

// APIKeyInput 是创建凭证时写入的字段，哈希与前缀由 service 生成。
type APIKeyInput struct {
	Name      string
	KeyPrefix string
	KeyHash   string
	ProjectID *int64
	Scopes    []string
	ExpiresAt *time.Time
	CreatedBy string
}

// APIKeyRepo 是 api_keys 的唯一数据入口。
type APIKeyRepo struct{ r *Repo }

func (r *Repo) APIKeys() *APIKeyRepo { return &APIKeyRepo{r: r} }

const apiKeyColumns = `k.id, k.name, k.key_prefix, k.project_id,
	coalesce(p.code, ''), coalesce(p.name, ''), k.scopes, k.enabled,
	k.expires_at, k.last_used_at, k.request_count, coalesce(k.created_by, ''), k.created_at`

func scanAPIKey(row pgx.Row) (*APIKey, error) {
	var k APIKey
	err := row.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.ProjectID, &k.ProjectCode, &k.ProjectName,
		&k.Scopes, &k.Enabled, &k.ExpiresAt, &k.LastUsedAt, &k.RequestCount, &k.CreatedBy, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if k.Scopes == nil {
		k.Scopes = []string{}
	}
	return &k, nil
}

func (a *APIKeyRepo) Create(ctx context.Context, in APIKeyInput) (*APIKey, error) {
	if in.Scopes == nil {
		in.Scopes = []string{"assets:read"}
	}
	var id int64
	err := a.r.pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, key_prefix, key_hash, project_id, scopes, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))
		RETURNING id`,
		in.Name, in.KeyPrefix, in.KeyHash, in.ProjectID, textArray(in.Scopes),
		timeToPGPtr(in.ExpiresAt), in.CreatedBy).Scan(&id)
	if err != nil {
		return nil, err
	}
	return a.Get(ctx, id)
}

func (a *APIKeyRepo) Get(ctx context.Context, id int64) (*APIKey, error) {
	return scanAPIKey(a.r.pool.QueryRow(ctx, `SELECT `+apiKeyColumns+`
		FROM api_keys k LEFT JOIN projects p ON p.id = k.project_id
		WHERE k.id = $1`, id))
}

// GetByHash 是鉴权热路径：哈希命中后再由 service 校验启用状态与有效期。
func (a *APIKeyRepo) GetByHash(ctx context.Context, hash string) (*APIKey, error) {
	return scanAPIKey(a.r.pool.QueryRow(ctx, `SELECT `+apiKeyColumns+`
		FROM api_keys k LEFT JOIN projects p ON p.id = k.project_id
		WHERE k.key_hash = $1`, hash))
}

func (a *APIKeyRepo) List(ctx context.Context) ([]*APIKey, error) {
	rows, err := a.r.pool.Query(ctx, `SELECT `+apiKeyColumns+`
		FROM api_keys k LEFT JOIN projects p ON p.id = k.project_id
		ORDER BY k.created_at DESC, k.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Touch 记录一次成功调用。MCP 调用量不大，同步写回即可；
// 以后真正成为热路径时再换成内存聚合 + 定时落库。
func (a *APIKeyRepo) Touch(ctx context.Context, id int64) error {
	_, err := a.r.pool.Exec(ctx,
		`UPDATE api_keys SET last_used_at = now(), request_count = request_count + 1 WHERE id = $1`, id)
	return err
}

func (a *APIKeyRepo) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	tag, err := a.r.pool.Exec(ctx, `UPDATE api_keys SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (a *APIKeyRepo) Delete(ctx context.Context, id int64) error {
	tag, err := a.r.pool.Exec(ctx, `DELETE FROM api_keys WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ProjectIDBySiteID 用于详情类工具的项目归属校验：
// 先确认站点存在且属于 key 授权范围，再决定是否返回详情。
func (a *APIKeyRepo) ProjectIDBySiteID(ctx context.Context, siteID int64) (int64, error) {
	var projectID int64
	err := a.r.pool.QueryRow(ctx, `SELECT project_id FROM sites WHERE id = $1`, siteID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return projectID, err
}

// timeToPGPtr 保留 nil 语义：NULL 表示永不过期。
func timeToPGPtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}
