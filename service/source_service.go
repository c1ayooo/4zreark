package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

// SourceService 数据源配置与连通性测试（G4）。
// 凭据写入后再也读不出来：列表/详情只回 has_secret。
type SourceService struct{}

func NewSourceService() *SourceService { return &SourceService{} }

var sourceKinds = map[string]bool{
	"fofa": true, "hunter": true, "quake": true, "zoomeye": true, "shodan": true,
	"crtsh": true, "wayback": true, "github": true, "gitlab": true, "appstore": true,
	"import": true, "custom": true,
}

type SourceInput struct {
	Kind     string         `json:"kind"`
	Name     string         `json:"name"`
	Endpoint string         `json:"endpoint"`
	Enabled  bool           `json:"enabled"`
	Config   map[string]any `json:"config"`
	// Secret 只在写入时使用；库里存密文，响应里不返回。
	Secret string `json:"secret,omitempty"`
}

type SourceTestResult struct {
	OK        bool   `json:"ok"`
	Status    int    `json:"status"`
	Message   string `json:"message"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

func (s *SourceService) repo() (repo.SourceRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Sources(), nil
}

func (s *SourceService) List(ctx context.Context) ([]*repo.Source, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.List(ctx)
}

func (s *SourceService) Get(ctx context.Context, id int64) (*repo.Source, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.Get(ctx, id)
}

func (s *SourceService) Create(ctx context.Context, in SourceInput) (*repo.Source, error) {
	if err := validateSourceInput(in, true); err != nil {
		return nil, err
	}
	r, err := s.repo()
	if err != nil {
		return nil, err
	}

	src := &repo.Source{
		Kind: in.Kind, Name: in.Name, Endpoint: in.Endpoint, Enabled: in.Enabled, Config: in.Config,
	}
	if in.Secret != "" {
		ref := "src_" + randomHex(8)
		ct, nonce, err := EncryptSecret(in.Secret)
		if err != nil {
			return nil, err
		}
		if err := r.SaveCredential(ctx, ref, ct, nonce); err != nil {
			return nil, err
		}
		src.CredentialRef = ref
	}
	if err := r.Create(ctx, src); err != nil {
		if src.CredentialRef != "" {
			_ = r.DeleteCredential(ctx, src.CredentialRef)
		}
		return nil, err
	}
	src.HasSecret = src.CredentialRef != ""
	return src, nil
}

func (s *SourceService) Update(ctx context.Context, id int64, in SourceInput) (*repo.Source, error) {
	if err := validateSourceInput(in, false); err != nil {
		return nil, err
	}
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	src, err := r.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	src.Kind, src.Name, src.Endpoint, src.Enabled = in.Kind, in.Name, in.Endpoint, in.Enabled
	if in.Config != nil {
		src.Config = in.Config
	}
	if in.Secret != "" {
		if src.CredentialRef == "" {
			src.CredentialRef = "src_" + randomHex(8)
		}
		ct, nonce, err := EncryptSecret(in.Secret)
		if err != nil {
			return nil, err
		}
		if err := r.SaveCredential(ctx, src.CredentialRef, ct, nonce); err != nil {
			return nil, err
		}
	}
	if err := r.Update(ctx, src); err != nil {
		return nil, err
	}
	src.HasSecret = src.CredentialRef != ""
	return src, nil
}

func (s *SourceService) Delete(ctx context.Context, id int64) error {
	r, err := s.repo()
	if err != nil {
		return err
	}
	return r.Delete(ctx, id)
}

// Test 发最小请求验证连通性。没有 endpoint 时只校验凭据是否已配置。
func (s *SourceService) Test(ctx context.Context, id int64) (*SourceTestResult, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	src, err := r.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	res := &SourceTestResult{}
	endpoint := strings.TrimSpace(src.Endpoint)
	// GitHub 类型没填 endpoint 时用 rate_limit 做最小鉴权校验。
	if endpoint == "" && src.Kind == "github" && src.HasSecret {
		endpoint = "https://api.github.com/rate_limit"
	}
	if endpoint == "" {
		if !src.HasSecret {
			_ = r.RecordTest(ctx, id, false, "未配置 endpoint 或凭据")
			return nil, errors.New("未配置 endpoint 或凭据")
		}
		_ = r.RecordTest(ctx, id, true, "")
		res.OK = true
		res.Message = "凭据已配置（无 endpoint，跳过网络测试）"
		return res, nil
	}

	// 审计 M6：凭据测试的 endpoint 必须落在 GitHub 主机白名单内——
	// 已存 token 只发给官方/显式批准的企业版主机，不跟随重定向。
	if err := CheckSourceEndpointHost(endpoint); err != nil {
		_ = r.RecordTest(ctx, id, false, err.Error())
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	// GitHub 必须带 token 才叫“测试凭据”，否则匿名请求只能证明网络通。
	if src.Kind == "github" && src.CredentialRef != "" {
		ct, nonce, cerr := r.LoadCredential(ctx, src.CredentialRef)
		if cerr == nil {
			if plain, derr := DecryptSecret(ct, nonce); derr == nil && strings.TrimSpace(plain) != "" {
				req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(plain))
			}
		}
	}
	// 不跟随重定向：Authorization 头不得被 30x 带去别的主机。
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	res.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		_ = r.RecordTest(ctx, id, false, err.Error())
		res.Message = err.Error()
		return res, nil
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		res.OK = true
		res.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		_ = r.RecordTest(ctx, id, true, "")
	} else {
		res.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		_ = r.RecordTest(ctx, id, false, res.Message)
	}
	return res, nil
}

// EngineKeys 返回引擎 key：sources 表（启用且带凭据）优先，全局配置兜底。
func (s *SourceService) EngineKeys(ctx context.Context) map[string]string {
	out := map[string]string{}
	if c := config.Loaded(); c != nil {
		put := func(k, v string) {
			if strings.TrimSpace(v) != "" {
				out[k] = v
			}
		}
		put("fofa", c.ThirdParty.Fofa.Key)
		put("hunter", c.ThirdParty.Hunter.Key)
		put("quake", c.ThirdParty.Quake.Key)
		put("zoomeye", c.ThirdParty.ZoomEye.Key)
		put("shodan", c.ThirdParty.Shodan.Key)
	}
	r, err := s.repo()
	if err != nil {
		return out
	}
	items, err := r.List(ctx)
	if err != nil {
		return out
	}
	for _, src := range items {
		if !src.Enabled || src.CredentialRef == "" {
			continue
		}
		ct, nonce, err := r.LoadCredential(ctx, src.CredentialRef)
		if err != nil {
			continue
		}
		plain, err := DecryptSecret(ct, nonce)
		if err != nil || strings.TrimSpace(plain) == "" {
			continue
		}
		out[src.Kind] = plain
	}
	return out
}

func (s *SourceService) EngineKey(ctx context.Context, provider string) string {
	return s.EngineKeys(ctx)[strings.ToLower(strings.TrimSpace(provider))]
}

// GitHubToken 统一解析 GitHub 凭据：环境变量优先，其次 sources 表里的密文凭据。
// 情报富化与指纹上游同步共用，避免两个入口各自只认环境变量。
func (s *SourceService) GitHubToken(ctx context.Context) string {
	if v := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); v != "" {
		return v
	}
	return s.EngineKey(ctx, "github")
}

// LegacyConfig 兼容旧 /thirdparty/config 的响应形状（key 脱敏）。
func (s *SourceService) LegacyConfig(ctx context.Context) (map[string]string, []string, error) {
	keys := s.EngineKeys(ctx)
	configured := make([]string, 0, 6)
	for _, k := range []string{"fofa", "hunter", "quake", "zoomeye", "shodan", "securitytrails"} {
		if keys[k] != "" {
			configured = append(configured, k)
		}
	}
	return map[string]string{
		"fofa_key":           maskKey(keys["fofa"]),
		"hunter_key":         maskKey(keys["hunter"]),
		"quake_key":          maskKey(keys["quake"]),
		"securitytrails_key": maskKey(keys["securitytrails"]),
		"zoomeye_key":        maskKey(keys["zoomeye"]),
		"shodan_key":         maskKey(keys["shodan"]),
	}, configured, nil
}

// UpdateLegacy 兼容旧 /thirdparty/config：写 sources 表（密文）。
func (s *SourceService) UpdateLegacy(ctx context.Context, body map[string]string) ([]string, error) {
	pairs := map[string]string{
		"fofa_key": "fofa", "hunter_key": "hunter", "quake_key": "quake",
		"securitytrails_key": "securitytrails", "zoomeye_key": "zoomeye", "shodan_key": "shodan",
	}
	for field, kind := range pairs {
		secret := strings.TrimSpace(body[field])
		if secret == "" {
			continue
		}
		if err := s.upsertEngineSource(ctx, kind, secret, nil); err != nil {
			return nil, fmt.Errorf("upsert %s: %w", kind, err)
		}
	}
	_, configured, _ := s.LegacyConfig(ctx)
	return configured, nil
}

func (s *SourceService) upsertEngineSource(ctx context.Context, kind, secret string, cfg map[string]any) error {
	r, err := s.repo()
	if err != nil {
		return err
	}
	src, err := r.FindByKind(ctx, kind)
	if errors.Is(err, repo.ErrNotFound) {
		src = &repo.Source{Kind: kind, Name: kind, Enabled: true, Config: cfg}
		if src.Config == nil {
			src.Config = map[string]any{}
		}
		if secret != "" {
			ref := "src_" + randomHex(8)
			ct, nonce, eerr := EncryptSecret(secret)
			if eerr != nil {
				return eerr
			}
			if eerr := r.SaveCredential(ctx, ref, ct, nonce); eerr != nil {
				return eerr
			}
			src.CredentialRef = ref
		}
		return r.Create(ctx, src)
	}
	if err != nil {
		return err
	}
	if cfg != nil {
		src.Config = cfg
	}
	if secret != "" {
		if src.CredentialRef == "" {
			src.CredentialRef = "src_" + randomHex(8)
		}
		ct, nonce, eerr := EncryptSecret(secret)
		if eerr != nil {
			return eerr
		}
		if eerr := r.SaveCredential(ctx, src.CredentialRef, ct, nonce); eerr != nil {
			return eerr
		}
	}
	return r.Update(ctx, src)
}

func maskKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 4 {
		return "****"
	}
	return "****" + key[len(key)-4:]
}

func validateSourceInput(in SourceInput, requireName bool) error {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if !sourceKinds[kind] {
		return fmt.Errorf("不支持的数据源类型 %q", in.Kind)
	}
	if requireName && strings.TrimSpace(in.Name) == "" {
		return errors.New("数据源名称不能为空")
	}
	return nil
}
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// allowedSourceHosts 是凭据测试允许的 GitHub 主机白名单（审计 M6）。
// 企业版（GHE）主机用 ZRE_GITHUB_EXTRA_HOSTS（逗号分隔域名）显式放行。
func allowedSourceHosts() map[string]bool {
	hosts := map[string]bool{
		"github.com":       true,
		"api.github.com":   true,
		"raw.github.com":   true,
		"gist.github.com":  true,
	}
	if extra := strings.TrimSpace(os.Getenv("ZRE_GITHUB_EXTRA_HOSTS")); extra != "" {
		for _, h := range strings.Split(extra, ",") {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				hosts[h] = true
			}
		}
	}
	return hosts
}

// CheckSourceEndpointHost 校验 endpoint 的 scheme 与主机：
// 必须 https 且主机精确命中白名单（防 "evil-github.com" 这类后缀仿冒）。
func CheckSourceEndpointHost(endpoint string) error {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("endpoint 必须是完整的 https URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !allowedSourceHosts()[host] {
		return fmt.Errorf("endpoint 主机 %q 不在 GitHub 白名单内（企业版主机用 ZRE_GITHUB_EXTRA_HOSTS 放行）", host)
	}
	return nil
}
