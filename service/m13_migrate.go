package service

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/secretbox"
	"github.com/c1ayooo/4zreark/repo"
)

// 安全审计 M13 的存量迁移：把历史上以明文落库的四类凭据重新加密。
// 双读已保证共存期可用（读路径对不带 enc:v1: 前缀的值原样返回），
// 本迁移把明文行改写为密文，收敛到「库内凭据只有密文」的终态。
//
// 运行时机：main 数据层就绪后调用，进程生命周期内执行一次；
// 未配置 ZRE_SECRET_KEY 时跳过并告警（存量保持明文，与改造前行为一致）。
// 幂等：只处理不带前缀的行，重复执行无副作用。

// MigratePlaintextSecrets 迁移数据源会话 / GitHub Token 池 / 监控设置 / 通知配置。
func MigratePlaintextSecrets(ctx context.Context) {
	if !secretbox.HasKey() {
		log.Printf("[M13] 未配置 ZRE_SECRET_KEY，跳过存量凭据加密迁移（新写入仍会被拒绝，配置后重启自动迁移）")
		return
	}
	r := repo.Default()
	if r == nil {
		return
	}
	mctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	total := 0
	// 1) 数据源会话：cookie / password
	total += migrateSessionColumn(mctx, "cookie")
	total += migrateSessionColumn(mctx, "password")
	// 2) GitHub Token 池
	total += migrateTokenPool(mctx)
	// 3) GitHub 监控设置
	total += migrateMonitorTokens(mctx)
	// 4) 通知配置 JSON（密钥字段）
	total += migrateNotifyConfigs(mctx)

	// 5) 审计 M5 收尾：清空幂等缓存的历史响应体——修复前的版本曾把
	// API Key / 节点 token 的明文存进 idempotency_keys.body（24h TTL）。
	// 三个一次性秘密端点已跳过缓存，不会再积累；清空后重放视为未缓存
	// 重新执行，语义安全。整表删除等价于一次缓存冷启动。
	if tag, err := r.Pool().Exec(mctx, `delete from idempotency_keys`); err != nil {
		log.Printf("[M13] 清理幂等缓存历史响应失败: %v", err)
	} else if tag.RowsAffected() > 0 {
		log.Printf("[M13] 已清理幂等缓存历史响应 %d 条（可能含修复前落库的秘密明文）", tag.RowsAffected())
	}

	if total > 0 {
		log.Printf("[M13] 存量凭据迁移完成：共加密 %d 个字段", total)
	} else {
		log.Printf("[M13] 存量凭据迁移：无需迁移（全部已加密或无数据）")
	}
}

// migrateSessionColumn 对 datasource_sessions 的单列做逐行加密。
func migrateSessionColumn(ctx context.Context, column string) int {
	r := repo.Default()
	rows, err := r.Pool().Query(ctx,
		`select provider, `+column+` from datasource_sessions where `+column+` <> '' and `+column+` not like 'enc:v1:%'`)
	if err != nil {
		log.Printf("[M13] 读取 datasource_sessions.%s 失败: %v", column, err)
		return 0
	}
	type kv struct{ provider, plain string }
	var items []kv
	for rows.Next() {
		var provider, plain string
		if err := rows.Scan(&provider, &plain); err == nil {
			items = append(items, kv{provider, plain})
		}
	}
	rows.Close()
	n := 0
	for _, it := range items {
		enc, err := secretbox.EncryptText(it.plain)
		if err != nil {
			log.Printf("[M13] 会话 %s 的 %s 加密失败，保留明文: %v", it.provider, column, err)
			continue
		}
		if _, err := r.Pool().Exec(ctx,
			`update datasource_sessions set `+column+` = $1, updated_at = now() where provider = $2`, enc, it.provider); err == nil {
			n++
		}
	}
	return n
}

func migrateTokenPool(ctx context.Context) int {
	r := repo.Default()
	rows, err := r.Pool().Query(ctx,
		`select id, token from github_token_pool where token not like 'enc:v1:%'`)
	if err != nil {
		log.Printf("[M13] 读取 github_token_pool 失败: %v", err)
		return 0
	}
	type kv struct{ id, plain string }
	var items []kv
	for rows.Next() {
		var id, plain string
		if err := rows.Scan(&id, &plain); err == nil && plain != "" {
			items = append(items, kv{id, plain})
		}
	}
	rows.Close()
	n := 0
	for _, it := range items {
		enc, err := secretbox.EncryptText(it.plain)
		if err != nil {
			log.Printf("[M13] token %s 加密失败，保留明文: %v", it.id, err)
			continue
		}
		if _, err := r.Pool().Exec(ctx,
			`update github_token_pool set token = $1, updated_at = now() where id = $2`, enc, it.id); err == nil {
			n++
		}
	}
	return n
}

func migrateMonitorTokens(ctx context.Context) int {
	r := repo.Default()
	rows, err := r.Pool().Query(ctx,
		`select project_id, token from github_monitor_settings where token <> '' and token not like 'enc:v1:%'`)
	if err != nil {
		log.Printf("[M13] 读取 github_monitor_settings 失败: %v", err)
		return 0
	}
	type kv struct{ id int64; plain string }
	var items []kv
	for rows.Next() {
		var id int64
		var plain string
		if err := rows.Scan(&id, &plain); err == nil {
			items = append(items, kv{id, plain})
		}
	}
	rows.Close()
	n := 0
	for _, it := range items {
		enc, err := secretbox.EncryptText(it.plain)
		if err != nil {
			log.Printf("[M13] 项目 %d 监控 token 加密失败，保留明文: %v", it.id, err)
			continue
		}
		if _, err := r.Pool().Exec(ctx,
			`update github_monitor_settings set token = $1, updated = now() where project_id = $2`, enc, it.id); err == nil {
			n++
		}
	}
	return n
}

// notifySecretJSONKeys 是通知渠道配置 JSON 里的密钥字段名。
var notifySecretJSONKeys = []string{
	"dingtalk_secret", "feishu_secret", "feishu_app_secret", "smtp_password",
}

func migrateNotifyConfigs(ctx context.Context) int {
	r := repo.Default()
	rows, err := r.Pool().Query(ctx,
		`select id, config from notify_configs where config::text like '%password%' or config::text like '%secret%'`)
	if err != nil {
		log.Printf("[M13] 读取 notify_configs 失败（表可能不存在）: %v", err)
		return 0
	}
	type kv struct {
		id     int64
		config []byte
	}
	var items []kv
	for rows.Next() {
		var id int64
		var cfg []byte
		if err := rows.Scan(&id, &cfg); err == nil {
			items = append(items, kv{id, cfg})
		}
	}
	rows.Close()
	n := 0
	for _, it := range items {
		enc, changed, err := encryptNotifyJSON(it.config)
		if err != nil {
			log.Printf("[M13] 通知配置 %d 迁移失败: %v", it.id, err)
			continue
		}
		if !changed {
			continue
		}
		if _, err := r.Pool().Exec(ctx,
			`update notify_configs set config = $1 where id = $2`, enc, it.id); err == nil {
			n++
		}
	}
	return n
}

// encryptNotifyJSON 把通知配置 JSON 里的明文密钥字段替换为密文。
// 返回（新 JSON，是否有改动，错误）；已有 enc:v1: 前缀的值跳过（幂等）。
// 密文比明文长，必须返回新切片而不是就地覆写。
func encryptNotifyJSON(config []byte) ([]byte, bool, error) {
	var m map[string]any
	if err := json.Unmarshal(config, &m); err != nil {
		return config, false, err
	}
	changed := false
	for _, key := range notifySecretJSONKeys {
		v, ok := m[key].(string)
		if !ok || v == "" || strings.HasPrefix(v, secretbox.Prefix) {
			continue
		}
		enc, err := secretbox.EncryptText(v)
		if err != nil {
			return config, changed, err
		}
		m[key] = enc
		changed = true
	}
	if !changed {
		return config, false, nil
	}
	out, err := json.Marshal(m)
	if err != nil {
		return config, changed, err
	}
	return out, true, nil
}
