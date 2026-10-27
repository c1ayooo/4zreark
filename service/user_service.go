package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/c1ayooo/4zreark/oid"
)

// dbTimeout 与改造前保持一致：调用方不传超时，统一 10s。
const dbTimeout = 10 * time.Second

type UserService struct{}

func NewUserService() *UserService {
	return &UserService{}
}

// users 延迟解析仓储：中间件在包初始化时就会构造 service，此时连接池还没建立。
func (s *UserService) users() (repo.UserRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Users(), nil
}

func dbCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), dbTimeout)
}

// Register creates a new user
func (s *UserService) Register(username, password, email string) (*models.User, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return nil, err
	}

	if _, err := ur.GetByUsername(ctx, username); err == nil {
		return nil, errors.New("用户名已存在")
	} else if !errors.Is(err, repo.ErrNotFound) {
		return nil, errors.New("查询用户失败")
	}

	exists, err := ur.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("查询邮箱失败")
	}
	if exists {
		return nil, errors.New("邮箱已被注册")
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, errors.New("密码加密失败")
	}

	now := time.Now()
	user := &models.User{
		ID:        oid.NewObjectID(),
		Username:  username,
		Password:  hashedPassword,
		Email:     email,
		Role:      "user",
		Status:    1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := ur.Create(ctx, user); err != nil {
		return nil, errors.New("创建用户失败")
	}
	return user, nil
}

// RegisterWithCode 使用注册码注册：消费注册码与建用户在同一个事务里。
func (s *UserService) RegisterWithCode(username, password, email, code string) (*models.User, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return nil, err
	}
	if _, err := ur.GetByUsername(ctx, username); err == nil {
		return nil, errors.New("用户名已存在")
	} else if !errors.Is(err, repo.ErrNotFound) {
		return nil, errors.New("查询用户失败")
	}
	exists, err := ur.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("查询邮箱失败")
	}
	if exists {
		return nil, errors.New("邮箱已被注册")
	}
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, errors.New("密码加密失败")
	}
	now := time.Now()
	user := &models.User{
		ID:        oid.NewObjectID(),
		Username:  username,
		Password:  hashedPassword,
		Email:     email,
		Status:    1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	if err := r.RegistrationCodes().CreateUserWithCode(ctx, user, code); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("注册码无效、已用完或已过期")
		}
		return nil, err
	}
	return user, nil
}

// Login authenticates user and returns JWT token
func (s *UserService) Login(username, password string) (string, *models.User, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return "", nil, err
	}

	user, err := ur.GetByUsername(ctx, username)
	if err != nil {
		log.Printf("[Login] User not found: %s", username)
		return "", nil, errors.New("用户名或密码错误")
	}

	if !utils.CheckPassword(password, user.Password) {
		log.Printf("[Login] Password check failed for user: %s", username)
		return "", nil, errors.New("用户名或密码错误")
	}

	if user.Status != 1 {
		return "", nil, errors.New("用户已被禁用")
	}

	token, err := utils.GenerateTokenClaims(user.ID.Hex(), user.Username, user.Role, user.TokenVersion, user.MustChangePassword)
	if err != nil {
		return "", nil, errors.New("生成Token失败")
	}

	if err := ur.TouchLastLogin(ctx, user.ID.Hex()); err != nil {
		log.Printf("[Login] 更新最后登录时间失败: %v", err)
	} else {
		user.LastLogin = time.Now()
	}

	return token, user, nil
}

// GetUserByID retrieves user by ID
func (s *UserService) GetUserByID(userID string) (*models.User, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return nil, err
	}

	user, err := ur.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.New("用户不存在")
	}
	return user, nil
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(userID string, updates map[string]interface{}) error {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return err
	}

	if err := ur.UpdateFields(ctx, userID, updates); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("用户不存在")
		}
		return errors.New("更新用户失败")
	}
	return nil
}

// ChangePassword changes user password
func (s *UserService) ChangePassword(userID, oldPassword, newPassword string) error {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return err
	}

	user, err := ur.GetByID(ctx, userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	if !utils.CheckPassword(oldPassword, user.Password) {
		return errors.New("原密码错误")
	}

	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("密码加密失败")
	}

	// 改密后旧 token 立即失效，需重新登录
	if err := ur.SetPassword(ctx, userID, hashedPassword, true); err != nil {
		return errors.New("修改密码失败")
	}
	return nil
}

// ListUsers lists all users with pagination
func (s *UserService) ListUsers(page, pageSize int, keyword string) ([]*models.User, int64, error) {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return nil, 0, err
	}

	users, total, err := ur.List(ctx, page, pageSize, keyword)
	if err != nil {
		return nil, 0, errors.New("查询用户列表失败")
	}
	return users, total, nil
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(userID string) error {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return err
	}

	if err := ur.Delete(ctx, userID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("用户不存在")
		}
		return errors.New("删除用户失败")
	}
	return nil
}

// SetUserStatus enables or disables a user
func (s *UserService) SetUserStatus(userID string, status int) error {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return err
	}

	if err := ur.SetStatus(ctx, userID, status); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("用户不存在")
		}
		return errors.New("更新用户状态失败")
	}
	return nil
}

// InitAdmin creates default admin user if not exists.
// 安全基线（审计 H2）：不再使用固定的公开默认口令。新建管理员时生成随机口令，
// 仅在创建那一次打印到 stdout（配合 MustChangePassword 强制首登改密）；
// 自动化部署可用 ZRE_ADMIN_PASSWORD 显式注入初始口令。存量库不受影响，
// 仍在用旧默认口令 admin123 的账户会被补强制改密标记。
func (s *UserService) InitAdmin() error {
	ctx, cancel := dbCtx()
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return err
	}

	initialPassword, err := generateAdminPassword()
	if err != nil {
		return err
	}
	hashedPassword, err := utils.HashPassword(initialPassword)
	if err != nil {
		return err
	}

	created, err := ur.EnsureAdmin(ctx, &models.User{
		ID:       oid.NewObjectID(),
		Username: "admin",
		Password: hashedPassword,
		Email:    "admin@localhost",
		Role:     "admin",
		Status:   1,
		// 初始口令只出现这一次：置强制改密标记，登录后只能改密直到完成。
		MustChangePassword: true,
	})
	if err != nil {
		return errors.New("创建管理员账户失败")
	}
	if created {
		log.Printf("[InitAdmin] Admin user created successfully")
		log.Printf("[InitAdmin] ===== admin 初始口令（仅此一次显示，请立即登录修改）: %s =====", initialPassword)
	} else {
		log.Printf("[InitAdmin] Admin user already exists")
		// 存量部署：默认口令未改则补上强制改密标记（迁移加列后这里兜底补数据）。
		if admin, gerr := ur.GetByUsername(ctx, "admin"); gerr == nil && admin != nil &&
			utils.CheckPassword("admin123", admin.Password) {
			log.Printf("[InitAdmin] 警告：admin 账户仍在使用旧默认口令，已置强制改密标记，请立即修改。")
			if !admin.MustChangePassword {
				if uerr := ur.UpdateFields(ctx, admin.ID.Hex(),
					map[string]any{"must_change_password": true}); uerr != nil {
					log.Printf("[InitAdmin] 置强制改密标记失败: %v", uerr)
				}
			}
		}
	}
	return nil
}

// generateAdminPassword 生成初始管理员口令：env 显式注入优先（自动化部署），
// 否则 crypto/rand 生成 20 位无歧义字符随机串（去掉 0O1lI 等易混字符）。
func generateAdminPassword() (string, error) {
	if v := strings.TrimSpace(os.Getenv("ZRE_ADMIN_PASSWORD")); v != "" {
		if len(v) < 12 {
			return "", errors.New("ZRE_ADMIN_PASSWORD 至少 12 位")
		}
		return v, nil
	}
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 20)
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("生成随机口令失败: " + err.Error())
	}
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

// hashToken 只存摘要：库里不出现令牌原文。
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// BlacklistToken 单端登出：把当前 token 写进黑名单，直到它自然过期。
func (s *UserService) BlacklistToken(token string) error {
	claims, err := utils.ParseToken(token)
	if err != nil {
		// Token 本身无效，无需登记
		return nil
	}
	if claims.ExpiresAt == nil || time.Until(claims.ExpiresAt.Time) <= 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return err
	}
	return ur.BlacklistToken(ctx, hashToken(token), claims.UserID, claims.ExpiresAt.Time)
}

// IsTokenRevoked 一次查询同时校验「单端登出黑名单」与「全端失效版本号」。
// 安全基线（审计 M2）：数据层错误时返回 error，由调用方失败关闭（拒绝认证），
// 不再按可用性优先放行——吊销检查失灵期间，被吊销的令牌必须拿不到任何授权。
func (s *UserService) IsTokenRevoked(token string, userID string, ver int) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ur, err := s.users()
	if err != nil {
		return false, err
	}
	revoked, err := ur.IsTokenRevoked(ctx, hashToken(token), userID, ver)
	if err != nil {
		log.Printf("[Auth] 校验 token 失败: %v", err)
		return false, err
	}
	return revoked, nil
}
