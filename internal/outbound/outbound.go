// Package outbound 是平台自身出网的统一代理解析层。
//
// 配置存 app_settings（key=network.proxy），由 service 层读写；本包不依赖数据层，
// 进程启动时由 main 注入存储（SetStore）。各出网客户端构造处按模块取代理：
//
//	client := outbound.HTTPClient("recon", 30*time.Second)
//	tr.Proxy = outbound.ProxyFuncFor("tool_download")
//
// 模块语义：
//   - custom → 使用模块自己的代理地址；
//   - direct → 强制直连（连环境变量代理也不走）；
//   - global/未配置 → 全局代理开启则走全局，否则跟随 HTTP(S)_PROXY 环境变量（既有行为）。
//
// 只覆盖平台自身出网（规则同步、工具下载、情报、被动收集、通知等），
// 面向扫描目标的请求不走这里，出口 IP 语义与扫描任务无关。
package outbound

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SettingsKey 配置在 app_settings 里的键。
const SettingsKey = "network.proxy"

// 模块覆盖模式。
const (
	ModeGlobal = "global"
	ModeDirect = "direct"
	ModeCustom = "custom"
)

// 平台自身出网的模块清单。保存时校验白名单，运行时未知模块视为程序错误。
var moduleNames = []string{"fingerprint_sync", "nuclei", "tool_download", "intel", "recon", "notify"}

// Modules 返回全部模块名（前端按此渲染）。
func Modules() []string { return append([]string(nil), moduleNames...) }

// ValidModule 报告模块名是否在白名单内。
func ValidModule(m string) bool {
	for _, name := range moduleNames {
		if name == m {
			return true
		}
	}
	return false
}

// ProxyEntry 全局代理配置。
type ProxyEntry struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

// Override 单模块覆盖。
type Override struct {
	Mode string `json:"mode"` // global | direct | custom
	URL  string `json:"url"`  // 仅 custom 使用
}

// Config network.proxy 的存储结构。
type Config struct {
	Global  ProxyEntry          `json:"global"`
	Modules map[string]Override `json:"modules"`
}

// Validate 校验并规范化配置：补齐缺失模块、清掉非 custom 的 URL。
// 返回规范化后的副本，可直接落库。
func Validate(cfg Config) (Config, error) {
	out := Config{
		Global:  ProxyEntry{Enabled: cfg.Global.Enabled, URL: strings.TrimSpace(cfg.Global.URL)},
		Modules: make(map[string]Override, len(moduleNames)),
	}
	if out.Global.URL != "" {
		if _, err := ParseProxyURL(out.Global.URL); err != nil {
			return out, fmt.Errorf("全局代理: %w", err)
		}
	}
	if out.Global.Enabled && out.Global.URL == "" {
		return out, errors.New("全局代理已启用但地址为空")
	}
	known := make(map[string]bool, len(moduleNames))
	for name, ov := range cfg.Modules {
		if !ValidModule(name) {
			return out, fmt.Errorf("未知模块 %q", name)
		}
		mode := strings.TrimSpace(ov.Mode)
		if mode == "" {
			mode = ModeGlobal
		}
		switch mode {
		case ModeGlobal, ModeDirect:
			out.Modules[name] = Override{Mode: mode}
		case ModeCustom:
			u := strings.TrimSpace(ov.URL)
			if _, err := ParseProxyURL(u); err != nil {
				return out, fmt.Errorf("模块 %s: %w", name, err)
			}
			out.Modules[name] = Override{Mode: ModeCustom, URL: u}
		default:
			return out, fmt.Errorf("模块 %s 的模式 %q 无效（可选 global/direct/custom）", name, ov.Mode)
		}
		known[name] = true
	}
	// 未显式出现的模块补默认值，存储里的结构始终完整。
	for _, name := range moduleNames {
		if _, ok := out.Modules[name]; !ok {
			out.Modules[name] = Override{Mode: ModeGlobal}
		}
	}
	return out, nil
}

// ParseProxyURL 校验代理地址：协议限定 http/https/socks5/socks5h，必须带 host。
// 凭据允许写在 URL 里（socks5://user:pass@host:1080）。保存与连通性测试共用。
func ParseProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("代理地址为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("代理地址无法解析: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q（可选 http/https/socks5/socks5h）", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("代理地址缺少 host")
	}
	return u, nil
}

// Store outbound 需要的最小存储接口；repo.SettingsRepo 天然满足。
type Store interface {
	Get(ctx context.Context, key string, out any) (bool, error)
}

const defaultTTL = 30 * time.Second

// Resolver 读取并缓存 network.proxy 配置。
// TTL 内命中缓存；Invalidate 后重读；存储读取失败时沿用上次配置（不因存储抖动全量直连）。
type Resolver struct {
	store  Store
	ttl    time.Duration
	mu     sync.Mutex
	cached *Config
	at     time.Time
}

// NewResolver 构造解析器；store 可为 nil（视为未配置，全部走环境变量语义）。
func NewResolver(store Store) *Resolver {
	return &Resolver{store: store, ttl: defaultTTL}
}

// 进程级单例：main 在数据层就绪后 SetStore，各出网点直接用包级函数。
var defaultResolver = NewResolver(nil)

// SetStore 注入进程级存储（可替换）。
func SetStore(s Store) {
	defaultResolver.mu.Lock()
	defer defaultResolver.mu.Unlock()
	defaultResolver.store = s
	defaultResolver.cached = nil
}

// Default 返回进程级解析器。
func Default() *Resolver { return defaultResolver }

// Reload 让进程级缓存立即失效（保存配置后调用）。
func Reload() { defaultResolver.Invalidate() }

// Invalidate 标记缓存过期，下次读取重查存储（不丢上次配置，存储读不到时沿用）。
func (r *Resolver) Invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.at = time.Time{}
}

func (r *Resolver) config(ctx context.Context) *Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cached != nil && time.Since(r.at) < r.ttl {
		return r.cached
	}
	if r.store != nil {
		var cfg Config
		ok, err := r.store.Get(ctx, SettingsKey, &cfg)
		if err == nil && ok {
			r.cached = &cfg
			r.at = time.Now()
			return r.cached
		}
		// 读不到（未配置/存储抖动）：沿用上次配置，避免抖动瞬间全量改道。
		if r.cached != nil {
			r.at = time.Now()
			return r.cached
		}
	}
	return nil
}

// resolve 返回模块的生效模式与代理地址（u=nil 表示无代理）。
func (r *Resolver) resolve(ctx context.Context, module string) (string, *url.URL, error) {
	if !ValidModule(module) {
		return "", nil, fmt.Errorf("未知出网模块 %q", module)
	}
	cfg := r.config(ctx)
	if cfg == nil {
		return ModeGlobal, nil, nil
	}
	ov := cfg.Modules[module] // 零值 Mode="" 按跟随全局处理
	switch strings.TrimSpace(ov.Mode) {
	case ModeDirect:
		return ModeDirect, nil, nil
	case ModeCustom:
		u, err := ParseProxyURL(ov.URL)
		if err != nil {
			return ModeCustom, nil, fmt.Errorf("模块 %s: %w", module, err)
		}
		return ModeCustom, u, nil
	default:
		if cfg.Global.Enabled {
			if strings.TrimSpace(cfg.Global.URL) == "" {
				return ModeGlobal, nil, errors.New("全局代理已启用但地址为空")
			}
			u, err := ParseProxyURL(cfg.Global.URL)
			if err != nil {
				return ModeGlobal, nil, fmt.Errorf("全局代理: %w", err)
			}
			return ModeGlobal, u, nil
		}
		return ModeGlobal, nil, nil
	}
}

// ProxyFor 返回模块应使用的代理；nil = 无代理（direct 或全局未开启）。
func (r *Resolver) ProxyFor(ctx context.Context, module string) (*url.URL, error) {
	_, u, err := r.resolve(ctx, module)
	return u, err
}

// ModeFor 返回模块生效模式（custom/global/direct）。
// 未知模块、存储不可用或未配置时返回 global（调用方据此走环境变量语义）。
func (r *Resolver) ModeFor(ctx context.Context, module string) string {
	mode, _, err := r.resolve(ctx, module)
	if err != nil {
		return ModeGlobal
	}
	return mode
}

// ProxyFuncFor 返回可直接放进 http.Transport.Proxy 的函数：
//   - 解析到代理 → 恒定返回该代理；
//   - direct → nil（真直连，忽略环境变量）；
//   - 跟随全局且全局未开启 → http.ProxyFromEnvironment（保持既有行为）；
//   - 配置非法 → 记日志并回退环境变量，不让坏配置断网。
func (r *Resolver) ProxyFuncFor(ctx context.Context, module string) func(*http.Request) (*url.URL, error) {
	mode, u, err := r.resolve(ctx, module)
	if err != nil {
		log.Printf("[outbound] 模块 %s 代理配置无效，暂按环境变量处理: %v", module, err)
		return http.ProxyFromEnvironment
	}
	switch {
	case mode == ModeDirect:
		return nil
	case u != nil:
		return func(*http.Request) (*url.URL, error) { return u, nil }
	default:
		return http.ProxyFromEnvironment
	}
}

// HTTPClient 按模块代理构造带超时的客户端，供按请求新建客户端的出网点使用。
func (r *Resolver) HTTPClient(ctx context.Context, module string, timeout time.Duration) *http.Client {
	tr := &http.Transport{Proxy: r.ProxyFuncFor(ctx, module)}
	c := &http.Client{Transport: tr}
	if timeout > 0 {
		c.Timeout = timeout
	}
	return c
}

// ---------------------------------------------------------------- 进程级快捷入口

// ProxyFor 进程级解析。
func ProxyFor(module string) (*url.URL, error) {
	return defaultResolver.ProxyFor(context.Background(), module)
}

// ProxyFuncFor 进程级解析，见 Resolver.ProxyFuncFor。
func ProxyFuncFor(module string) func(*http.Request) (*url.URL, error) {
	return defaultResolver.ProxyFuncFor(context.Background(), module)
}

// ModeFor 进程级解析模块生效模式（custom/global/direct）。
func ModeFor(module string) string {
	return defaultResolver.ModeFor(context.Background(), module)
}

// ProxyURLFor 返回模块代理的字符串形式（req/v3 SetProxyURL、子进程环境变量用）；空 = 无代理。
func ProxyURLFor(module string) string {
	u, err := ProxyFor(module)
	if err != nil {
		log.Printf("[outbound] 模块 %s 代理配置无效: %v", module, err)
		return ""
	}
	if u == nil {
		return ""
	}
	return u.String()
}

// HTTPClient 进程级按模块构造客户端。
func HTTPClient(module string, timeout time.Duration) *http.Client {
	return defaultResolver.HTTPClient(context.Background(), module, timeout)
}
