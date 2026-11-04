package service

import (
	"context"
	"errors"
	"log"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

// MCPGovernanceService 是 MCP 治理面的管理端：工具总闸的查看与启停、
// 速率配额的查看与调整。走 JWT 管理员，与 API key 的 scope 权限分离。
type MCPGovernanceService struct{}

func NewMCPGovernanceService() *MCPGovernanceService { return &MCPGovernanceService{} }

// settingsKey 是治理面在 app_settings 里的单例键。
const mcpGovernanceSettingsKey = "mcp_governance"

// MCPGovernanceSettings 是可热更新的治理参数；零值字段回落默认值。
type MCPGovernanceSettings struct {
	RateLimitPerMin int `json:"rate_limit_per_min"`
}

// MCPToolState 是治理页一行的工具状态。
type MCPToolState struct {
	Name        string   `json:"name"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes"`
	AnyScopes   []string `json:"any_scopes,omitempty"`
	Write       bool     `json:"write"`
	Enabled     bool     `json:"enabled"`
}

// Overview 返回全部工具的元数据 + 总闸状态（无记录视为启用）。
func (s *MCPGovernanceService) Overview(ctx context.Context) ([]MCPToolState, MCPGovernanceSettings, error) {
	settings, err := s.LoadSettings(ctx)
	if err != nil {
		return nil, settings, err
	}
	sw, err := switchMap(ctx)
	if err != nil {
		return nil, settings, err
	}
	metas := NewMCPService().ToolMetas()
	out := make([]MCPToolState, 0, len(metas))
	for _, m := range metas {
		enabled := true
		if v, ok := sw[m.Name]; ok {
			enabled = v
		}
		out = append(out, MCPToolState{
			Name: m.Name, Title: m.Title, Description: m.Description,
			Scopes: m.Scopes, AnyScopes: m.AnyScopes, Write: m.Write,
			Enabled: enabled,
		})
	}
	return out, settings, nil
}

// ErrMCPToolUnknown 表示工具名不在注册表中。
var ErrMCPToolUnknown = errors.New("未知工具")

// SetToolEnabled 写入工具总闸。工具名必须在注册表中，防止拼错的名字
// 看起来设置成功、实际永远不生效。
func (s *MCPGovernanceService) SetToolEnabled(ctx context.Context, tool string, enabled bool) error {
	for _, m := range NewMCPService().ToolMetas() {
		if m.Name == tool {
			g := mcpGovernance()
			if g == nil {
				return errors.New("数据层未初始化")
			}
			return g.SetToolSwitch(ctx, tool, enabled)
		}
	}
	return ErrMCPToolUnknown
}

// LoadSettings 读取治理参数；键不存在或读取失败时回落默认值。
func (s *MCPGovernanceService) LoadSettings(ctx context.Context) (MCPGovernanceSettings, error) {
	out := MCPGovernanceSettings{RateLimitPerMin: s.rateLimitFallback()}
	r := repo.Default()
	if r == nil {
		return out, nil
	}
	var stored MCPGovernanceSettings
	found, err := r.Settings().Get(ctx, mcpGovernanceSettingsKey, &stored)
	if err != nil {
		return out, nil // 读取失败按默认值走，不阻塞治理页
	}
	if found && stored.RateLimitPerMin > 0 {
		out.RateLimitPerMin = stored.RateLimitPerMin
	}
	return out, nil
}

// SaveSettings 持久化治理参数（配额调整立即生效，无需重启）。
func (s *MCPGovernanceService) SaveSettings(ctx context.Context, in MCPGovernanceSettings) (MCPGovernanceSettings, error) {
	if in.RateLimitPerMin < 1 || in.RateLimitPerMin > 600 {
		return MCPGovernanceSettings{}, errors.New("rate_limit_per_min 需在 1-600 之间")
	}
	r := repo.Default()
	if r == nil {
		return MCPGovernanceSettings{}, errors.New("数据层未初始化")
	}
	if err := r.Settings().Set(ctx, mcpGovernanceSettingsKey, in); err != nil {
		return MCPGovernanceSettings{}, err
	}
	return in, nil
}

// rateLimitFallback 依次取配置文件值与内置默认。
func (s *MCPGovernanceService) rateLimitFallback() int {
	if cfg := config.Loaded(); cfg != nil && cfg.MCP.RateLimitPerMin > 0 {
		return cfg.MCP.RateLimitPerMin
	}
	return MCPDefaultRateLimit
}

// switchMap 拉全量开关成 map；失败时返回空 map（全部视为启用），不打断治理页。
func switchMap(ctx context.Context) (map[string]bool, error) {
	g := mcpGovernance()
	if g == nil {
		return map[string]bool{}, nil
	}
	states, err := g.ListToolSwitches(ctx)
	if err != nil {
		log.Printf("[MCPGovernance] 读取工具开关失败（按全部启用处理）: %v", err)
		return map[string]bool{}, nil
	}
	m := make(map[string]bool, len(states))
	for _, st := range states {
		m[st.Tool] = st.Enabled
	}
	return m, nil
}
