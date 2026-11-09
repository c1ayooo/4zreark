package service

// GitHub Token 池（平台级，多 token）。
//
// 为什么是池：GitHub API/克隆限流按 token 计（匿名 60 次/小时，token 5000），
// 监控十几个仓库时单 token 不够用。存取沿用 llm.config 的形态：
// app_settings JSON + secretbox 信封加密，回显只给掩码。
// 消费方：sentinel 采集（clone/fetch 轮询取一个注入认证头）。

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/secretbox"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/oid"
)

const githubTokensKey = "github.tokens"

// GitHubTokenEntry 是池里的一条 token（cipher 为密文，不出库）。
type GitHubTokenEntry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Cipher    string    `json:"-"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type githubTokensRecord struct {
	Tokens []GitHubTokenEntry `json:"tokens"`
}

// GitHubTokenView 是给前端的一条：掩码，不带密文。
type GitHubTokenView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Masked    string    `json:"masked"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	ghTokenMu       sync.Mutex
	ghTokenCache    *githubTokensRecord
	ghTokenCachedAt time.Time
	ghTokenCounter  uint64
)

func invalidateGitHubTokens() {
	ghTokenMu.Lock()
	ghTokenCache = nil
	ghTokenMu.Unlock()
}

// loadGitHubTokens 带锁读取（外部调用入口）。
func loadGitHubTokens(ctx context.Context) (*githubTokensRecord, error) {
	ghTokenMu.Lock()
	defer ghTokenMu.Unlock()
	return loadGitHubTokensLocked(ctx)
}

// loadGitHubTokensLocked 无锁读取：调用方必须已持有 ghTokenMu
// （Add/Delete 外层持锁再进这里，非重入锁会死锁——已踩过）。
func loadGitHubTokensLocked(ctx context.Context) (*githubTokensRecord, error) {
	if ghTokenCache != nil && time.Since(ghTokenCachedAt) < 10*time.Second {
		return ghTokenCache, nil
	}
	rec := &githubTokensRecord{}
	found, err := repo.Default().Settings().Get(ctx, githubTokensKey, rec)
	if err != nil {
		return nil, err
	}
	if !found {
		rec = &githubTokensRecord{Tokens: []GitHubTokenEntry{}}
	}
	ghTokenCache = rec
	ghTokenCachedAt = time.Now()
	return rec, nil
}

func saveGitHubTokens(ctx context.Context, rec *githubTokensRecord) error {
	ghTokenMu.Lock()
	defer ghTokenMu.Unlock()
	return saveGitHubTokensLocked(ctx, rec)
}

// saveGitHubTokensLocked 无锁写库并更新缓存：调用方必须已持有 ghTokenMu。
func saveGitHubTokensLocked(ctx context.Context, rec *githubTokensRecord) error {
	if err := repo.Default().Settings().Set(ctx, githubTokensKey, rec); err != nil {
		return err
	}
	// 调用方已持有 ghTokenMu，这里直接更新缓存（再 Lock = 自锁，已踩过）。
	ghTokenCache = rec
	ghTokenCachedAt = time.Now()
	return nil
}

// ListGitHubTokens 返回掩码视图。
func ListGitHubTokens(ctx context.Context) ([]GitHubTokenView, error) {
	rec, err := loadGitHubTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GitHubTokenView, 0, len(rec.Tokens))
	for _, t := range rec.Tokens {
		out = append(out, GitHubTokenView{
			ID: t.ID, Name: t.Name, Masked: maskGitHubToken(t.Cipher),
			Enabled: t.Enabled, CreatedAt: t.CreatedAt,
		})
	}
	return out, nil
}

// AddGitHubToken 新增一条：名字可空（默认 gh-token-N），token 走 secretbox。
func AddGitHubToken(ctx context.Context, name, token string) (*GitHubTokenView, error) {
	token = strings.TrimSpace(token)
	if len(token) < 20 {
		return nil, fmt.Errorf("token 长度不合法（github_pat_/ghp_/gho_ 开头的完整 token）")
	}
	cipher, err := secretbox.EncryptText(token)
	if err != nil {
		return nil, fmt.Errorf("加密失败: %w", err)
	}
	ghTokenMu.Lock()
	defer ghTokenMu.Unlock()
	rec, err := loadGitHubTokensLocked(ctx)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = fmt.Sprintf("gh-token-%d", len(rec.Tokens)+1)
	}
	entry := GitHubTokenEntry{
		ID: oid.NewObjectID().Hex(), Name: name, Cipher: cipher,
		Enabled: true, CreatedAt: time.Now(),
	}
	rec.Tokens = append(rec.Tokens, entry)
	if err := saveGitHubTokensLocked(ctx, rec); err != nil {
		return nil, err
	}
	return &GitHubTokenView{ID: entry.ID, Name: entry.Name,
		Masked: maskGitHubToken(cipher), Enabled: true, CreatedAt: entry.CreatedAt}, nil
}

// DeleteGitHubToken 按 id 删除。
func DeleteGitHubToken(ctx context.Context, id string) error {
	ghTokenMu.Lock()
	defer ghTokenMu.Unlock()
	rec, err := loadGitHubTokensLocked(ctx)
	if err != nil {
		return err
	}
	out := rec.Tokens[:0]
	removed := false
	for _, t := range rec.Tokens {
		if t.ID == id {
			removed = true
			continue
		}
		out = append(out, t)
	}
	if !removed {
		return repo.ErrNotFound
	}
	rec.Tokens = out
	return saveGitHubTokensLocked(ctx, rec)
}

// PickGitHubToken 轮询取一个可用 token 的明文（采集认证用）。
// 池为空返回空串——调用方回退匿名克隆。
func PickGitHubToken(ctx context.Context) string {
	rec, err := loadGitHubTokens(ctx)
	if err != nil {
		return ""
	}
	enabled := make([]GitHubTokenEntry, 0, len(rec.Tokens))
	for _, t := range rec.Tokens {
		if t.Enabled {
			enabled = append(enabled, t)
		}
	}
	if len(enabled) == 0 {
		return ""
	}
	ghTokenCounter++
	tok, err := secretbox.DecryptText(enabled[ghTokenCounter%uint64(len(enabled))].Cipher)
	if err != nil {
		return ""
	}
	return tok
}

// GitHubTokenAuthArgs 返回采集用 git 认证参数（http.extraheader），
// token 只存在于单次命令行，不落 mirror 的 remote 配置。空池返回 nil。
func GitHubTokenAuthArgs(ctx context.Context) []string {
	tok := PickGitHubToken(ctx)
	if tok == "" {
		return nil
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + tok))
	return []string{"-c", "http.extraheader=AUTHORIZATION: basic " + b64}
}

// maskGitHubToken 头 7 尾 4，中间省略。
func maskGitHubToken(cipher string) string {
	plain, err := secretbox.DecryptText(cipher)
	if err != nil || len(plain) < 12 {
		return "****"
	}
	return plain[:7] + "…" + plain[len(plain)-4:]
}
