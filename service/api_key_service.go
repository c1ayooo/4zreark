package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

const (
	// APIKeyPrefix 让凭证在日志/配置里可识别，也避免和 JWT 混淆。
	APIKeyPrefix = "zr_"
)

var (
	ErrInvalidAPIKey  = errors.New("API key 无效")
	ErrAPIKeyDisabled = errors.New("API key 已禁用")
	ErrAPIKeyExpired  = errors.New("API key 已过期")
)

// APIKeyService 负责凭证的生成、列示、吊销与鉴权。
// 明文 key 只在 Create 的返回值里出现一次，后续任何查询都只有前缀。
type APIKeyService struct{}

func NewAPIKeyService() *APIKeyService { return &APIKeyService{} }

func (s *APIKeyService) repo() (*repo.APIKeyRepo, error) {
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	return repo.Default().APIKeys(), nil
}

// APIKeyInput 是管理员创建凭证时的输入。
type APIKeyInput struct {
	Name      string     `json:"name"`
	ProjectID *int64     `json:"project_id"` // nil = 所有项目
	Scopes    []string   `json:"scopes"`     // 空 = assets:read
	ExpiresAt *time.Time `json:"expires_at"` // nil = 永不过期
}

// CreatedAPIKey 是创建响应：key 字段之后无法再次获取。
type CreatedAPIKey struct {
	*repo.APIKey
	Key string `json:"key"`
}

func normalizeAPIKeyInput(in APIKeyInput) (APIKeyInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return in, errors.New("凭证名称必填")
	}
	if len([]rune(in.Name)) > 120 {
		return in, errors.New("凭证名称不超过 120 字")
	}
	// project_id = 0 视为「所有项目」，前端“全部项目”选项直接传 0。
	if in.ProjectID != nil && *in.ProjectID == 0 {
		in.ProjectID = nil
	}
	if in.ProjectID != nil && *in.ProjectID < 0 {
		return in, errors.New("项目 ID 非法")
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		return in, errors.New("过期时间必须晚于当前时间")
	}
	scopes, err := ValidateScopes(in.Scopes)
	if err != nil {
		return in, err
	}
	in.Scopes = scopes
	return in, nil
}

func (s *APIKeyService) List(ctx context.Context) ([]*repo.APIKey, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.List(ctx)
}

func (s *APIKeyService) Create(ctx context.Context, in APIKeyInput, createdBy string) (*CreatedAPIKey, error) {
	in, err := normalizeAPIKeyInput(in)
	if err != nil {
		return nil, err
	}
	if in.ProjectID != nil {
		ar := repo.NewAssetRepo()
		if _, err := ar.GetProject(ctx, *in.ProjectID); err != nil {
			if errors.Is(err, repo.ErrNotFound) {
				return nil, errors.New("绑定的项目不存在")
			}
			return nil, err
		}
	}

	raw, prefix, hash, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	k, err := r.Create(ctx, repo.APIKeyInput{
		Name:      in.Name,
		KeyPrefix: prefix,
		KeyHash:   hash,
		ProjectID: in.ProjectID,
		Scopes:    in.Scopes,
		ExpiresAt: in.ExpiresAt,
		CreatedBy: createdBy,
	})
	if err != nil {
		return nil, err
	}
	return &CreatedAPIKey{APIKey: k, Key: raw}, nil
}

func (s *APIKeyService) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	r, err := s.repo()
	if err != nil {
		return err
	}
	return r.SetEnabled(ctx, id, enabled)
}

func (s *APIKeyService) Delete(ctx context.Context, id int64) error {
	r, err := s.repo()
	if err != nil {
		return err
	}
	return r.Delete(ctx, id)
}

// Authenticate 校验明文 key。只有启用且未过期的凭证能通过；
// 通过后同步记一次调用，便于管理员在设置页看到最近使用时间。
func (s *APIKeyService) Authenticate(ctx context.Context, raw string) (*repo.APIKey, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, APIKeyPrefix) {
		return nil, ErrInvalidAPIKey
	}
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])

	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	k, err := r.GetByHash(ctx, hash)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, ErrInvalidAPIKey
	}
	if err != nil {
		return nil, err
	}
	if !k.Enabled {
		return nil, ErrAPIKeyDisabled
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(time.Now()) {
		return nil, ErrAPIKeyExpired
	}
	_ = r.Touch(ctx, k.ID)
	return k, nil
}

// generateAPIKey 生成 zr_ + 64 位十六进制明文，同时给出展示前缀与落库哈希。
func generateAPIKey() (raw, prefix, hash string, err error) {
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", "", err
	}
	raw = APIKeyPrefix + hex.EncodeToString(b[:])
	prefix = raw[:len(APIKeyPrefix)+8]
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, prefix, hash, nil
}
