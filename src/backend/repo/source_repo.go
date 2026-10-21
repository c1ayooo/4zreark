package repo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// 数据源与凭据（G4）。凭据只存 AES-256-GCM 密文，接口永不回显。
type Source struct {
	ID            int64          `json:"id"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Endpoint      string         `json:"endpoint"`
	Enabled       bool           `json:"enabled"`
	Config        map[string]any `json:"config"`
	CredentialRef string         `json:"-"`
	HasSecret     bool           `json:"has_secret"`
	LastOKAt      *time.Time     `json:"last_ok_at"`
	LastError     string         `json:"last_error"`
	CooldownUntil *time.Time     `json:"cooldown_until"`
	CreatedAt     time.Time      `json:"created_at"`
}

type SourceRepo interface {
	List(ctx context.Context) ([]*Source, error)
	Get(ctx context.Context, id int64) (*Source, error)
	FindByKind(ctx context.Context, kind string) (*Source, error)
	Create(ctx context.Context, s *Source) error
	Update(ctx context.Context, s *Source) error
	Delete(ctx context.Context, id int64) error

	SaveCredential(ctx context.Context, ref string, ciphertext, nonce []byte) error
	LoadCredential(ctx context.Context, ref string) (ciphertext, nonce []byte, err error)
	DeleteCredential(ctx context.Context, ref string) error
	RecordTest(ctx context.Context, id int64, ok bool, errMsg string) error
}

type sourceRepo struct{ r *Repo }

func (r *Repo) Sources() SourceRepo { return &sourceRepo{r: r} }

const sourceColumns = `id, kind, name, endpoint, enabled, config,
	coalesce(credential_ref, ''), last_ok_at, last_error, cooldown_until, created_at`

func scanSource(row interface{ Scan(...any) error }) (*Source, error) {
	var s Source
	var config []byte
	var ref string
	if err := row.Scan(&s.ID, &s.Kind, &s.Name, &s.Endpoint, &s.Enabled, &config,
		&ref, &s.LastOKAt, &s.LastError, &s.CooldownUntil, &s.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(config, &s.Config)
	if s.Config == nil {
		s.Config = map[string]any{}
	}
	s.CredentialRef = ref
	s.HasSecret = ref != ""
	return &s, nil
}

func (r *sourceRepo) List(ctx context.Context) ([]*Source, error) {
	rows, err := r.r.pool.Query(ctx, `select `+sourceColumns+` from sources order by kind, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Source{}
	for rows.Next() {
		s, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *sourceRepo) Get(ctx context.Context, id int64) (*Source, error) {
	return scanSource(r.r.pool.QueryRow(ctx, `select `+sourceColumns+` from sources where id = $1`, id))
}

// FindByKind 返回该类型下优先启用的一条数据源（kind 是引擎名：fofa/hunter/...）。
func (r *sourceRepo) FindByKind(ctx context.Context, kind string) (*Source, error) {
	return scanSource(r.r.pool.QueryRow(ctx,
		`select `+sourceColumns+` from sources where kind = $1 order by enabled desc, id limit 1`, kind))
}

func (r *sourceRepo) Create(ctx context.Context, s *Source) error {
	if s.Config == nil {
		s.Config = map[string]any{}
	}
	return r.r.pool.QueryRow(ctx, `
insert into sources (kind, name, endpoint, enabled, config, credential_ref)
values ($1,$2,$3,$4,$5,nullif($6,''))
returning id, created_at`,
		s.Kind, s.Name, s.Endpoint, s.Enabled, toJSONB(s.Config), s.CredentialRef).
		Scan(&s.ID, &s.CreatedAt)
}

func (r *sourceRepo) Update(ctx context.Context, s *Source) error {
	if s.Config == nil {
		s.Config = map[string]any{}
	}
	tag, err := r.r.pool.Exec(ctx, `
update sources set kind=$2, name=$3, endpoint=$4, enabled=$5, config=$6,
       credential_ref = nullif($7, '')
 where id = $1`,
		s.ID, s.Kind, s.Name, s.Endpoint, s.Enabled, toJSONB(s.Config), s.CredentialRef)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *sourceRepo) Delete(ctx context.Context, id int64) error {
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var ref string
	if err := tx.QueryRow(ctx, `select coalesce(credential_ref,'') from sources where id=$1`, id).Scan(&ref); err != nil {
		return err
	}
	if ref != "" {
		if _, err := tx.Exec(ctx, `delete from source_credentials where ref=$1`, ref); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `delete from sources where id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *sourceRepo) SaveCredential(ctx context.Context, ref string, ciphertext, nonce []byte) error {
	_, err := r.r.pool.Exec(ctx, `
insert into source_credentials (ref, ciphertext, nonce, updated_at)
values ($1,$2,$3,now())
on conflict (ref) do update set ciphertext=excluded.ciphertext, nonce=excluded.nonce, updated_at=now()`,
		ref, ciphertext, nonce)
	return err
}

func (r *sourceRepo) LoadCredential(ctx context.Context, ref string) ([]byte, []byte, error) {
	var ct, nonce []byte
	err := r.r.pool.QueryRow(ctx,
		`select ciphertext, nonce from source_credentials where ref=$1`, ref).Scan(&ct, &nonce)
	return ct, nonce, err
}

func (r *sourceRepo) DeleteCredential(ctx context.Context, ref string) error {
	_, err := r.r.pool.Exec(ctx, `delete from source_credentials where ref=$1`, ref)
	return err
}

func (r *sourceRepo) RecordTest(ctx context.Context, id int64, ok bool, errMsg string) error {
	if ok {
		_, err := r.r.pool.Exec(ctx,
			`update sources set last_ok_at=now(), last_error='' where id=$1`, id)
		return err
	}
	_, err := r.r.pool.Exec(ctx, `update sources set last_error=$2 where id=$1`, id, errMsg)
	return err
}
