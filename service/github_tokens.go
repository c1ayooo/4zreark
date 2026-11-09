package service

// GitHub Token 池（平台级唯一池）。
//
// 历史上这里是一条独立的池（app_settings github.tokens JSON，简单轮询），
// 与监控面板的 github_token_pool 表（internal/githubtokens，带配额管理）并存，
// 导致「设置页加了 token、监控/情报却看不到」的割裂。现已合并：
// 存储统一收敛到 github_token_pool 表（功能超集：按剩余配额轮换、启停、
// 占位值校验、去重、配额采集），本文件只保留统一池的单例装配与
// 采集认证取号（git clone 不受 API 配额影响，绕过配额过滤直接轮转）。
//
// 消费方：sentinel 采集（git 认证头）、GitHub 泄露监控（API 轮询）、
// 情报富化（PoC 检索）；三个管理入口（/github/tokens、/github-tokens、面板）
// 读写的是同一张表。

import (
	"context"
	"encoding/base64"
	"log"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/c1ayooo/4zreark/internal/githubtokens"
	"github.com/c1ayooo/4zreark/internal/secretbox"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/jackc/pgx/v5/stdlib"
)

var (
	ghPoolOnce  sync.Once
	ghPoolStore *githubtokens.Store
	ghPool      *githubtokens.Pool
)

// initGitHubTokenPool 构造统一池单例（表由 Store 自建）；DB 未就绪时不阻塞，
// 返回 nil 由调用方降级（监控退回项目级单 token，采集回退匿名克隆）。
func initGitHubTokenPool() (*githubtokens.Store, *githubtokens.Pool) {
	ghPoolOnce.Do(func() {
		r := repo.Default()
		if r == nil {
			return
		}
		sqldb := stdlib.OpenDBFromPool(r.Pool())
		store, err := githubtokens.NewStore(sqldb)
		if err != nil {
			log.Printf("[GitHubTokens] 统一 Token 池初始化失败: %v", err)
			return
		}
		ghPoolStore = store
		ghPool = githubtokens.NewPool(store)
	})
	return ghPoolStore, ghPool
}

// GitHubTokenStore 统一池存储访问（管理端点列表/删除/配额展示用）；未就绪返回 nil。
func GitHubTokenStore() *githubtokens.Store {
	s, _ := initGitHubTokenPool()
	return s
}

// GitHubTokenPool 统一池轮换器访问（监控热更/手动刷新配额用）；未就绪返回 nil。
func GitHubTokenPool() *githubtokens.Pool {
	_, p := initGitHubTokenPool()
	return p
}

var ghPickCounter atomic.Uint64

// PickGitHubToken 轮询取一个启用 token 的明文（git 采集认证用）。
// 与 Pool.Pick 的配额优先策略刻意不同：API 配额打满不影响 git 认证，
// 这里对全部启用号做 rr 轮转，把配额压力均摊到每个号。
// 池为空/未就绪返回空串——调用方回退匿名克隆。
func PickGitHubToken(ctx context.Context) string {
	store := GitHubTokenStore()
	if store == nil {
		return ""
	}
	tokens, err := store.List(ctx)
	if err != nil {
		log.Printf("[GitHubTokens] 读取统一池失败（回退匿名克隆）: %v", err)
		return ""
	}
	enabled := make([]githubtokens.Token, 0, len(tokens))
	for _, t := range tokens {
		if t.Enabled && t.Token != "" {
			enabled = append(enabled, t)
		}
	}
	if len(enabled) == 0 {
		return ""
	}
	idx := ghPickCounter.Add(1) - 1
	return enabled[idx%uint64(len(enabled))].Token
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

// MigrateLegacyGitHubTokens 把旧 app_settings「github.tokens」池（独立 JSON 轮询池，
// 已废弃）的存量 token 一次性搬进统一池。旧 key 里存的是 secretbox 密文。
// 幂等：搬运成功即删除旧 key，重复执行无副作用；store.Add 自带去重与占位值拒绝。
func MigrateLegacyGitHubTokens(ctx context.Context) {
	store := GitHubTokenStore()
	if store == nil {
		return
	}
	var legacy struct {
		Tokens []struct {
			Name    string `json:"name"`
			Cipher  string `json:"cipher"`
			Enabled bool   `json:"enabled"`
		} `json:"tokens"`
	}
	found, err := repo.Default().Settings().Get(ctx, "github.tokens", &legacy)
	if err != nil || !found || len(legacy.Tokens) == 0 {
		return
	}
	moved := 0
	for _, t := range legacy.Tokens {
		plain, err := secretboxDecryptToken(t.Cipher)
		if err != nil || plain == "" {
			continue
		}
		if _, err := store.Add(ctx, t.Name, plain); err != nil {
			// 重复号/占位值不是故障：统一池已有同号或本来就是示例值，跳过即可
			log.Printf("[GitHubTokens] 旧池 token「%s」未搬入统一池: %v", t.Name, err)
			continue
		}
		moved++
	}
	if err := repo.Default().Settings().Delete(ctx, "github.tokens"); err != nil {
		log.Printf("[GitHubTokens] 清理旧 github.tokens 设置失败（下次启动会重试，重复号会被去重）: %v", err)
		return
	}
	log.Printf("[GitHubTokens] 旧 github.tokens 池已并入统一池：新增 %d/%d 条", moved, len(legacy.Tokens))
}

// secretboxDecryptToken 解开旧池条目的密文；未配置密钥或格式不对时返回错误。
func secretboxDecryptToken(cipher string) (string, error) {
	cipher = strings.TrimSpace(cipher)
	if cipher == "" {
		return "", nil
	}
	return secretbox.DecryptText(cipher)
}
