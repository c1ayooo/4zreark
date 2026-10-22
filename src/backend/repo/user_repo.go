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

// UserRepo 是用户与登录态的唯一数据入口。
// token 黑名单没有单开仓储：它和 users.token_version 一起构成登录态校验，归在用户域。
type UserRepo interface {
	Create(ctx context.Context, u *models.User) error
	GetByID(ctx context.Context, id string) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	UpdateFields(ctx context.Context, id string, fields map[string]any) error
	SetPassword(ctx context.Context, id, hashedPassword string, revokeTokens bool) error
	SetStatus(ctx context.Context, id string, status int) error
	List(ctx context.Context, page, pageSize int, keyword string) ([]*models.User, int64, error)
	Delete(ctx context.Context, id string) error
	TouchLastLogin(ctx context.Context, id string) error
	EnsureAdmin(ctx context.Context, u *models.User) (bool, error)
	BlacklistToken(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error
	IsTokenRevoked(ctx context.Context, tokenHash, userID string, ver int) (bool, error)
}

type userRepo struct{ r *Repo }

const userColumns = `id, username, password, email, phone, nickname, avatar,
	role, status, must_change_password, token_version, last_login, created_at, updated_at`

// userUpdatable 是允许被 UpdateFields 改动的列白名单：
// 键来自调用方（可能是 HTTP 请求体），必须映射到固定列名，绝不拼原始键。
var userUpdatable = map[string]string{
	"username":             "username",
	"email":                "email",
	"phone":                "phone",
	"nickname":             "nickname",
	"avatar":               "avatar",
	"role":                 "role",
	"status":               "status",
	"password":             "password",
	"must_change_password": "must_change_password",
}

func scanUser(row pgx.Row) (*models.User, error) {
	var (
		hexID     string
		u         models.User
		lastLogin *time.Time
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&hexID, &u.Username, &u.Password, &u.Email, &u.Phone, &u.Nickname,
		&u.Avatar, &u.Role, &u.Status, &u.MustChangePassword, &u.TokenVersion,
		&lastLogin, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	oid, err := oid.ObjectIDFromHex(hexID)
	if err != nil {
		return nil, fmt.Errorf("库里的 id 不是合法 ObjectID: %s", hexID)
	}
	u.ID = oid
	u.LastLogin = timeFromPG(lastLogin)
	u.CreatedAt = timeFromPG(&createdAt)
	u.UpdatedAt = timeFromPG(&updatedAt)
	return &u, nil
}

func (r *userRepo) Create(ctx context.Context, u *models.User) error {
	_, err := r.r.pool.Exec(ctx,
		`insert into users (id, username, password, email, phone, nickname, avatar,
		                    role, status, must_change_password, token_version, last_login, created_at, updated_at)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		u.ID.Hex(), u.Username, u.Password, u.Email, u.Phone, u.Nickname, u.Avatar,
		u.Role, u.Status, u.MustChangePassword, u.TokenVersion, timeToPG(u.LastLogin),
		timeToPG(u.CreatedAt), timeToPG(u.UpdatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("唯一约束冲突: %w", err)
		}
		return err
	}
	return nil
}

func (r *userRepo) GetByID(ctx context.Context, id string) (*models.User, error) {
	if _, err := idFromString(id); err != nil {
		return nil, ErrNotFound
	}
	return scanUser(r.r.pool.QueryRow(ctx,
		`select `+userColumns+` from users where id = $1`, id))
}

func (r *userRepo) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	return scanUser(r.r.pool.QueryRow(ctx,
		`select `+userColumns+` from users where username = $1`, username))
}

func (r *userRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	if email == "" {
		return false, nil
	}
	var exists bool
	err := r.r.pool.QueryRow(ctx,
		`select exists (select 1 from users where email = $1)`, email).Scan(&exists)
	return exists, err
}

func (r *userRepo) UpdateFields(ctx context.Context, id string, fields map[string]any) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}

	sets := make([]string, 0, len(fields)+1)
	args := make([]any, 0, len(fields)+2)
	i := 1
	for k, v := range fields {
		col, ok := userUpdatable[k]
		if !ok {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", col, i))
		args = append(args, v)
		i++
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)

	stmt := "update users set " + strings.Join(sets, ", ") + fmt.Sprintf(" where id = $%d", i)
	tag, err := r.r.pool.Exec(ctx, stmt, args...)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("唯一约束冲突: %w", err)
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *userRepo) SetPassword(ctx context.Context, id, hashedPassword string, revokeTokens bool) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	// 改密同时清除「必须改密」标记：强制改密流程到此闭环。
	stmt := `update users set password = $1, must_change_password = false, updated_at = now() where id = $2`
	if revokeTokens {
		// 改密后旧 token 立即失效
		stmt = `update users set password = $1, must_change_password = false, token_version = token_version + 1, updated_at = now() where id = $2`
	}
	tag, err := r.r.pool.Exec(ctx, stmt, hashedPassword, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *userRepo) SetStatus(ctx context.Context, id string, status int) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	// 禁用即踢下线：token_version 自增，旧 token 全部作废
	tag, err := r.r.pool.Exec(ctx,
		`update users set status = $1, token_version = token_version + 1, updated_at = now() where id = $2`,
		status, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *userRepo) List(ctx context.Context, page, pageSize int, keyword string) ([]*models.User, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	rows, err := r.r.pool.Query(ctx,
		`select `+userColumns+`, count(*) over() as total
		   from users
		  where ($1 = '' or username ilike '%' || $1 || '%'
		                  or email ilike '%' || $1 || '%'
		                  or nickname ilike '%' || $1 || '%')
		  order by created_at desc
		  limit $2 offset $3`,
		keyword, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var (
		users []*models.User
		total int64
	)
	for rows.Next() {
		var (
			hexID     string
			u         models.User
			lastLogin *time.Time
			createdAt time.Time
			updatedAt time.Time
			t         int64
		)
		if err := rows.Scan(&hexID, &u.Username, &u.Password, &u.Email, &u.Phone, &u.Nickname,
			&u.Avatar, &u.Role, &u.Status, &u.TokenVersion, &lastLogin, &createdAt, &updatedAt, &t); err != nil {
			return nil, 0, err
		}
		oid, err := oid.ObjectIDFromHex(hexID)
		if err != nil {
			return nil, 0, fmt.Errorf("库里的 id 不是合法 ObjectID: %s", hexID)
		}
		u.ID = oid
		u.LastLogin = timeFromPG(lastLogin)
		u.CreatedAt = timeFromPG(&createdAt)
		u.UpdatedAt = timeFromPG(&updatedAt)
		users = append(users, &u)
		total = t
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (r *userRepo) Delete(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	tag, err := r.r.pool.Exec(ctx, `delete from users where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *userRepo) TouchLastLogin(ctx context.Context, id string) error {
	if _, err := idFromString(id); err != nil {
		return ErrNotFound
	}
	_, err := r.r.pool.Exec(ctx, `update users set last_login = now() where id = $1`, id)
	return err
}

func (r *userRepo) EnsureAdmin(ctx context.Context, u *models.User) (bool, error) {
	tag, err := r.r.pool.Exec(ctx,
		`insert into users (id, username, password, email, role, status, must_change_password, token_version, created_at, updated_at)
		 values ($1,$2,$3,$4,$5,$6,$7,0,now(),now())
		 on conflict (username) do nothing`,
		u.ID.Hex(), u.Username, u.Password, u.Email, u.Role, u.Status, u.MustChangePassword)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *userRepo) BlacklistToken(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error {
	if _, err := r.r.pool.Exec(ctx,
		`insert into token_blacklist (token_hash, user_id, expires_at)
		 values ($1,$2,$3) on conflict (token_hash) do nothing`,
		tokenHash, userID, expiresAt); err != nil {
		return err
	}
	// 顺手清掉过期的，避免表无限增长（正式清理交给 reaper）
	_, _ = r.r.pool.Exec(ctx, `delete from token_blacklist where expires_at < now()`)
	return nil
}

func (r *userRepo) IsTokenRevoked(ctx context.Context, tokenHash, userID string, ver int) (bool, error) {
	if _, err := idFromString(userID); err != nil {
		return true, nil
	}
	var (
		curVer      int
		blacklisted bool
	)
	err := r.r.pool.QueryRow(ctx,
		`select coalesce((select token_version from users where id = $2), -1),
		        exists (select 1 from token_blacklist where token_hash = $1 and expires_at > now())`,
		tokenHash, userID).Scan(&curVer, &blacklisted)
	if err != nil {
		return false, err
	}
	// 用户被删（-1）或版本号对不上，都算失效
	return blacklisted || curVer != ver, nil
}
