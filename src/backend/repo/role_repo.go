package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// 角色 → 权限码。
type RoleRepo interface {
	Permissions(ctx context.Context, role string) ([]string, error)
	HasPermission(ctx context.Context, role, code string) (bool, error)
}

type roleRepo struct{ r *Repo }

func (r *Repo) Roles() RoleRepo { return &roleRepo{r: r} }

func (r *roleRepo) Permissions(ctx context.Context, role string) ([]string, error) {
	var perms []string
	err := r.r.pool.QueryRow(ctx, `select permissions from roles where name=$1`, role).Scan(&perms)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return perms, err
}

func (r *roleRepo) HasPermission(ctx context.Context, role, code string) (bool, error) {
	var ok bool
	err := r.r.pool.QueryRow(ctx,
		`select $2 = any(permissions) from roles where name=$1`, role, code).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return ok, err
}
