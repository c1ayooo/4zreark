package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// 数据源会话托管：企业数据源的会话持久化（扫码/Cookie/账号密码）。
// provider 与 internal/enterprise Registry 的 Name 一致。

type DatasourceSession struct {
	Provider    string     `json:"provider"`
	Cookie      string     `json:"cookie"`
	Username    string     `json:"username"`
	Password    string     `json:"password"`
	Status      string     `json:"status"` // unconfigured / active / expired
	LastLoginAt *time.Time `json:"last_login_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type DatasourceSessionRepo interface {
	// Get 未配置时返回 ErrNotFound。
	Get(ctx context.Context, provider string) (*DatasourceSession, error)
	// Upsert 整行覆盖（空字段即清空）；status 由调用方按语义给定。
	Upsert(ctx context.Context, s *DatasourceSession) error
	MarkStatus(ctx context.Context, provider, status string) error
	TouchLogin(ctx context.Context, provider string) error
	Delete(ctx context.Context, provider string) (bool, error)
	List(ctx context.Context) ([]*DatasourceSession, error)
}

type datasourceSessionRepo struct{ r *Repo }

func (r *Repo) DatasourceSessions() DatasourceSessionRepo { return &datasourceSessionRepo{r: r} }

const dsSessionCols = `provider, cookie, username, password, status, last_login_at, created_at, updated_at`

func (r *datasourceSessionRepo) Get(ctx context.Context, provider string) (*DatasourceSession, error) {
	row := r.r.pool.QueryRow(ctx,
		`select `+dsSessionCols+` from datasource_sessions where provider = $1`, provider)
	s, err := scanDatasourceSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

func (r *datasourceSessionRepo) Upsert(ctx context.Context, s *DatasourceSession) error {
	_, err := r.r.pool.Exec(ctx, `
insert into datasource_sessions (provider, cookie, username, password, status, last_login_at)
values ($1,$2,$3,$4,$5,$6)
on conflict (provider) do update set
    cookie = excluded.cookie, username = excluded.username, password = excluded.password,
    status = excluded.status, last_login_at = excluded.last_login_at, updated_at = now()`,
		s.Provider, s.Cookie, s.Username, s.Password, s.Status, s.LastLoginAt)
	return err
}

func (r *datasourceSessionRepo) MarkStatus(ctx context.Context, provider, status string) error {
	_, err := r.r.pool.Exec(ctx,
		`update datasource_sessions set status = $2, updated_at = now() where provider = $1`,
		provider, status)
	return err
}

func (r *datasourceSessionRepo) TouchLogin(ctx context.Context, provider string) error {
	_, err := r.r.pool.Exec(ctx,
		`update datasource_sessions set status = 'active', last_login_at = now(), updated_at = now() where provider = $1`,
		provider)
	return err
}

func (r *datasourceSessionRepo) Delete(ctx context.Context, provider string) (bool, error) {
	tag, err := r.r.pool.Exec(ctx, `delete from datasource_sessions where provider = $1`, provider)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *datasourceSessionRepo) List(ctx context.Context) ([]*DatasourceSession, error) {
	rows, err := r.r.pool.Query(ctx, `select `+dsSessionCols+` from datasource_sessions order by provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DatasourceSession{}
	for rows.Next() {
		s, err := scanDatasourceSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanDatasourceSession(rs rowScanner) (*DatasourceSession, error) {
	var (
		s         DatasourceSession
		createdAt time.Time
		updatedAt time.Time
	)
	if err := rs.Scan(&s.Provider, &s.Cookie, &s.Username, &s.Password, &s.Status,
		&s.LastLoginAt, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	s.CreatedAt = timeFromPG(&createdAt)
	s.UpdatedAt = timeFromPG(&updatedAt)
	return &s, nil
}
