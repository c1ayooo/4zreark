package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/jackc/pgx/v5"
)

// 注册码：管理员生成，注册时一次性/多次消费；消费与建用户在同一个事务里，
// 用户创建失败（重名/邮箱冲突）不会白白扣掉次数。

type RegistrationCode struct {
	Code      string     `json:"code"`
	Role      string     `json:"role"`
	MaxUses   int        `json:"max_uses"`
	UsedCount int        `json:"used_count"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

type RegistrationRepo interface {
	Create(ctx context.Context, code, role string, maxUses int, expiresAt *time.Time, createdBy string) error
	List(ctx context.Context, limit int) ([]*RegistrationCode, error)
	Delete(ctx context.Context, code string) (bool, error)
	DeleteBatch(ctx context.Context, codes []string) (int64, error)
	// CreateUserWithCode 在事务内消费注册码并创建用户；code 无效时不建用户。
	CreateUserWithCode(ctx context.Context, user *models.User, code string) error
}

type registrationRepo struct{ r *Repo }

func (r *Repo) RegistrationCodes() RegistrationRepo { return &registrationRepo{r: r} }

func (r *registrationRepo) Create(ctx context.Context, code, role string, maxUses int, expiresAt *time.Time, createdBy string) error {
	var by any
	if createdBy != "" {
		by = createdBy
	}
	_, err := r.r.pool.Exec(ctx, `
insert into registration_codes (code, role, max_uses, expires_at, created_by)
values ($1,$2,$3,$4,$5)`, code, role, maxUses, expiresAt, by)
	return err
}

func (r *registrationRepo) List(ctx context.Context, limit int) ([]*RegistrationCode, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.r.pool.Query(ctx, `
select code, role, max_uses, used_count, expires_at, coalesce(created_by,''), created_at
  from registration_codes
 order by created_at desc
 limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*RegistrationCode{}
	for rows.Next() {
		var c RegistrationCode
		if err := rows.Scan(&c.Code, &c.Role, &c.MaxUses, &c.UsedCount,
			&c.ExpiresAt, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.CreatedAt = timeFromPG(&c.CreatedAt)
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (r *registrationRepo) Delete(ctx context.Context, code string) (bool, error) {
	tag, err := r.r.pool.Exec(ctx, `delete from registration_codes where code=$1`, code)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *registrationRepo) DeleteBatch(ctx context.Context, codes []string) (int64, error) {
	if len(codes) == 0 {
		return 0, nil
	}
	tag, err := r.r.pool.Exec(ctx, `delete from registration_codes where code = any($1)`, codes)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *registrationRepo) CreateUserWithCode(ctx context.Context, user *models.User, code string) error {
	if user == nil || code == "" {
		return errors.New("注册码必填")
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var role string
	if err := tx.QueryRow(ctx, `
update registration_codes
   set used_count = used_count + 1
 where code = $1
   and used_count < max_uses
   and (expires_at is null or expires_at > now())
returning role`, code).Scan(&role); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	user.Role = role
	if _, err := tx.Exec(ctx, `
insert into users (id, username, password, email, phone, nickname, avatar, role, status, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		user.ID.Hex(), user.Username, user.Password, user.Email, user.Phone,
		user.Nickname, user.Avatar, user.Role, user.Status, user.CreatedAt, user.UpdatedAt); err != nil {
		return fmt.Errorf("创建用户失败: %w", err)
	}
	return tx.Commit(ctx)
}
