package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// RegistrationService 管理注册码。
type RegistrationService struct{}

func NewRegistrationService() *RegistrationService { return &RegistrationService{} }

func (s *RegistrationService) repo() (repo.RegistrationRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.RegistrationCodes(), nil
}

var registrationRoles = map[string]bool{
	"admin": true, "operator": true, "user": true, "viewer": true,
}

func validRegistrationRole(role string) bool { return registrationRoles[role] }

// Generate 批量生成注册码，返回明文列表（仅本次展示）。
func (s *RegistrationService) Generate(ctx context.Context, count int, role string, maxUses int, expiresAt *time.Time, createdBy string) ([]string, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		role = "user"
	}
	if !validRegistrationRole(role) {
		return nil, errors.New("角色只能是 admin / operator / user / viewer")
	}
	if count <= 0 || count > 100 {
		return nil, errors.New("单次生成数量需在 1..100")
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if maxUses > 1000 {
		return nil, errors.New("单码可用次数不能超过 1000")
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return nil, errors.New("过期时间不能早于当前时间")
	}
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		code, err := generateRegistrationCode()
		if err != nil {
			return out, err
		}
		if err := r.Create(ctx, code, role, maxUses, expiresAt, createdBy); err != nil {
			return out, fmt.Errorf("写入注册码失败: %w", err)
		}
		out = append(out, code)
	}
	return out, nil
}

func generateRegistrationCode() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "zc_" + hex.EncodeToString(b[:]), nil
}

func (s *RegistrationService) List(ctx context.Context, limit int) ([]*repo.RegistrationCode, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.List(ctx, limit)
}

func (s *RegistrationService) Delete(ctx context.Context, code string) error {
	r, err := s.repo()
	if err != nil {
		return err
	}
	ok, err := r.Delete(ctx, strings.TrimSpace(code))
	if err != nil {
		return err
	}
	if !ok {
		return repo.ErrNotFound
	}
	return nil
}

func (s *RegistrationService) DeleteBatch(ctx context.Context, codes []string) (int64, error) {
	r, err := s.repo()
	if err != nil {
		return 0, err
	}
	cleaned := make([]string, 0, len(codes))
	for _, c := range codes {
		if c = strings.TrimSpace(c); c != "" {
			cleaned = append(cleaned, c)
		}
	}
	if len(cleaned) == 0 {
		return 0, errors.New("codes 不能为空")
	}
	return r.DeleteBatch(ctx, cleaned)
}
