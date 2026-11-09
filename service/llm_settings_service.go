package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/internal/secretbox"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/cloudwego/eino/schema"
)

// 模型接入配置（app_settings: llm.config）。
//
// 此前 LLM 只能靠启动时的环境变量（ZRE_LLM_*）配置：改一次要重启，界面上也没有入口，
// 判定/对话要么用桩模型、要么靠人记住导出变量。这里把配置落到 app_settings，
// 密钥走 secretbox 加密（与 GitHub token 同一套），运行时按需读取、保存后立即生效。
const llmSettingsKey = "llm.config"

// 缓存窗口：判定是批量任务，逐条查库没必要；保存时显式失效。
const llmSettingsTTL = 10 * time.Second

// llmSettingsRecord 是落库形态（JSON），密钥为密文。
type llmSettingsRecord struct {
	BaseURL        string    `json:"base_url"`
	Model          string    `json:"model"`
	APIKey         string    `json:"api_key"`
	Temperature    float64   `json:"temperature"`
	MaxTokens      int       `json:"max_tokens"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	UpdatedAt      time.Time `json:"updated_at"`
	UpdatedBy      string    `json:"updated_by"`
}

// LLMSettingsView 是给前端的视图：密钥不出库，只回「是否已配置 + 掩码」。
type LLMSettingsView struct {
	BaseURL          string     `json:"base_url"`
	Model            string     `json:"model"`
	APIKeyConfigured bool       `json:"api_key_configured"`
	APIKeyMasked     string     `json:"api_key_masked"`
	Temperature      float64    `json:"temperature"`
	MaxTokens        int        `json:"max_tokens"`
	TimeoutSeconds   int        `json:"timeout_seconds"`
	// Source: db（界面配置）| env（环境变量）| none（都没配，判定走桩模型）
	Source    string     `json:"source"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// LLMSettingsInput 是保存入参。APIKey 为空表示「保持原密钥不变」，
// ClearKey=true 才清空（避免误把空输入当成清空）。
type LLMSettingsInput struct {
	BaseURL        string  `json:"base_url"`
	Model          string  `json:"model"`
	APIKey         string  `json:"api_key"`
	ClearKey       bool    `json:"clear_key"`
	Temperature    float64 `json:"temperature"`
	MaxTokens      int     `json:"max_tokens"`
	TimeoutSeconds int     `json:"timeout_seconds"`
}

var (
	llmSettingsMu     sync.Mutex
	llmSettingsCache  *llmSettingsRecord
	llmSettingsCached time.Time
	llmSettingsLoaded bool
)

// InvalidateLLMSettings 让下一次读取重新查库（保存后调用）。
func InvalidateLLMSettings() {
	llmSettingsMu.Lock()
	llmSettingsLoaded = false
	llmSettingsCache = nil
	llmSettingsMu.Unlock()
}

// loadLLMRecord 读配置，短 TTL 缓存；未配置返回 (nil,false,nil)。
func loadLLMRecord(ctx context.Context) (*llmSettingsRecord, bool, error) {
	llmSettingsMu.Lock()
	if llmSettingsLoaded && time.Since(llmSettingsCached) < llmSettingsTTL {
		rec := llmSettingsCache
		llmSettingsMu.Unlock()
		return rec, rec != nil, nil
	}
	llmSettingsMu.Unlock()

	rec := &llmSettingsRecord{}
	found, err := repo.Default().Settings().Get(ctx, llmSettingsKey, rec)
	if err != nil {
		return nil, false, err
	}

	llmSettingsMu.Lock()
	llmSettingsCached = time.Now()
	if found {
		llmSettingsCache = rec
	} else {
		llmSettingsCache = nil
	}
	llmSettingsLoaded = true
	llmSettingsMu.Unlock()

	if !found {
		return nil, false, nil
	}
	return rec, true, nil
}

// GetLLMSettings 返回当前生效配置的视图（DB 优先，其次环境变量）。
func GetLLMSettings(ctx context.Context) (*LLMSettingsView, error) {
	rec, found, err := loadLLMRecord(ctx)
	if err != nil {
		return nil, err
	}

	if found {
		key, derr := secretbox.DecryptText(rec.APIKey)
		if derr != nil {
			return nil, fmt.Errorf("解密模型密钥失败: %w", derr)
		}
		view := &LLMSettingsView{
			BaseURL:          rec.BaseURL,
			Model:            rec.Model,
			APIKeyConfigured: strings.TrimSpace(key) != "",
			APIKeyMasked:     maskSecret(key),
			Temperature:      rec.Temperature,
			MaxTokens:        rec.MaxTokens,
			TimeoutSeconds:   rec.TimeoutSeconds,
			Source:           "db",
		}
		if !rec.UpdatedAt.IsZero() {
			t := rec.UpdatedAt
			view.UpdatedAt = &t
		}
		view.UpdatedBy = rec.UpdatedBy
		return view, nil
	}

	// 退到环境变量：只读展示，改它去改环境变量。
	cfg := config.LLMConfig{}
	if loaded := config.Loaded(); loaded != nil {
		cfg = loaded.LLM
	}
	cfg.Normalize()
	key := strings.TrimSpace(cfg.EffectiveAPIKey())
	source := "none"
	if key != "" {
		source = "env"
	}
	return &LLMSettingsView{
		BaseURL:          cfg.BaseURL,
		Model:            cfg.Model,
		APIKeyConfigured: key != "",
		APIKeyMasked:     maskSecret(key),
		Temperature:      cfg.Temperature,
		MaxTokens:        cfg.MaxTokens,
		TimeoutSeconds:   cfg.TimeoutSeconds,
		Source:           source,
	}, nil
}

// SaveLLMSettings 保存配置；api_key 加密后落库，保存即生效（下一次读取命中新值）。
func SaveLLMSettings(ctx context.Context, in LLMSettingsInput, operator string) (*LLMSettingsView, error) {
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	in.Model = strings.TrimSpace(in.Model)
	if in.BaseURL == "" {
		return nil, errors.New("Base URL 不能为空（如 https://api.openai.com/v1）")
	}
	if in.Model == "" {
		return nil, errors.New("模型名不能为空（如 gpt-4o-mini / deepseek-chat）")
	}
	if !strings.HasPrefix(in.BaseURL, "http://") && !strings.HasPrefix(in.BaseURL, "https://") {
		return nil, errors.New("Base URL 需要以 http:// 或 https:// 开头")
	}

	old, found, err := loadLLMRecord(ctx)
	if err != nil {
		return nil, err
	}
	rec := &llmSettingsRecord{
		BaseURL:        in.BaseURL,
		Model:          in.Model,
		Temperature:    in.Temperature,
		MaxTokens:      in.MaxTokens,
		TimeoutSeconds: in.TimeoutSeconds,
		UpdatedAt:      time.Now(),
		UpdatedBy:      operator,
	}
	// 密钥三态：显式清空 / 传了新值 → 重新加密 / 留空 → 沿用旧密文。
	switch {
	case in.ClearKey:
		rec.APIKey = ""
	case strings.TrimSpace(in.APIKey) != "":
		enc, eerr := secretbox.EncryptText(strings.TrimSpace(in.APIKey))
		if eerr != nil {
			return nil, fmt.Errorf("加密模型密钥失败: %w", eerr)
		}
		rec.APIKey = enc
	case found:
		rec.APIKey = old.APIKey
	}

	if err := repo.Default().Settings().Set(ctx, llmSettingsKey, rec); err != nil {
		return nil, err
	}
	InvalidateLLMSettings()
	return GetLLMSettings(ctx)
}

// EffectiveLLMConfig 返回当前应使用的模型配置：DB 配置优先，缺项退回启动配置。
func EffectiveLLMConfig(ctx context.Context, fallback config.LLMConfig) config.LLMConfig {
	rec, found, err := loadLLMRecord(ctx)
	if err != nil || !found {
		return fallback
	}
	key, derr := secretbox.DecryptText(rec.APIKey)
	if derr != nil || strings.TrimSpace(key) == "" {
		return fallback
	}

	out := fallback
	if rec.BaseURL != "" {
		out.BaseURL = rec.BaseURL
	}
	if rec.Model != "" {
		out.Model = rec.Model
	}
	out.APIKey = strings.TrimSpace(key)
	// 清掉 env 名，否则 EffectiveAPIKey 还会去读环境变量覆盖掉界面配置。
	out.APIKeyEnv = ""
	if rec.Temperature > 0 {
		out.Temperature = rec.Temperature
	}
	if rec.MaxTokens > 0 {
		out.MaxTokens = rec.MaxTokens
	}
	if rec.TimeoutSeconds > 0 {
		out.TimeoutSeconds = rec.TimeoutSeconds
	}
	out.Normalize()
	return out
}

// TestLLMSettings 用给定参数（未填密钥时用库里已存的）发一次最小请求。
// 返回模型原话前 200 字，作为「真的连通了」的证据。
func TestLLMSettings(ctx context.Context, in LLMSettingsInput) (string, error) {
	cfg := config.LLMConfig{}
	if loaded := config.Loaded(); loaded != nil {
		cfg = loaded.LLM
	}
	if in.BaseURL != "" {
		cfg.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	}
	if in.Model != "" {
		cfg.Model = strings.TrimSpace(in.Model)
	}
	if strings.TrimSpace(in.APIKey) != "" {
		cfg.APIKey = strings.TrimSpace(in.APIKey)
		cfg.APIKeyEnv = ""
	} else if effective := EffectiveLLMConfig(ctx, cfg); strings.TrimSpace(effective.APIKey) != "" {
		cfg = effective
	}
	if in.TimeoutSeconds > 0 {
		cfg.TimeoutSeconds = in.TimeoutSeconds
	} else if cfg.TimeoutSeconds <= 0 || cfg.TimeoutSeconds > 30 {
		cfg.TimeoutSeconds = 30
	}
	if in.MaxTokens > 0 && in.MaxTokens < 64 {
		cfg.MaxTokens = in.MaxTokens
	} else {
		cfg.MaxTokens = 64
	}
	cfg.Normalize()
	if strings.TrimSpace(cfg.EffectiveAPIKey()) == "" {
		return "", errors.New("未配置 API Key")
	}

	cm, err := llm.NewChatModel(ctx, cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoKey) {
			return "", errors.New("未配置 API Key")
		}
		return "", fmt.Errorf("构建模型失败: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	msg, err := cm.Generate(callCtx, []*schema.Message{
		schema.SystemMessage("你是连通性探针，只回复两个字：可用"),
		schema.UserMessage("ping"),
	})
	if err != nil {
		return "", llm.Classify(err)
	}
	text := strings.TrimSpace(msg.Content)
	if len(text) > 200 {
		text = text[:200]
	}
	return text, nil
}

// maskSecret 只留头尾，长度不足以掩码时整体打码。
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
