package outbound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// fakeStore 以 map 充当 SettingsRepo，测试配置解析的读取路径。
type fakeStore struct {
	data  map[string][]byte // key → JSON
	miss  bool
	getN  int
	delay time.Duration
}

func (f *fakeStore) Get(_ context.Context, key string, out any) (bool, error) {
	f.getN++
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.miss {
		return false, nil
	}
	raw, ok := f.data[key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(raw, out)
}

func cfgJSON(t *testing.T, cfg Config) []byte {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// ---------------------------------------------------------------- Validate

func TestValidateAcceptsAndNormalizes(t *testing.T) {
	in := Config{
		Global: ProxyEntry{Enabled: true, URL: "socks5://u:p@10.0.0.1:1080"},
		Modules: map[string]Override{
			"tool_download": {Mode: "custom", URL: "http://127.0.0.1:7890"},
			"intel":         {Mode: "direct"},
		},
	}
	out, err := Validate(in)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if out.Global.URL != "socks5://u:p@10.0.0.1:1080" {
		t.Fatalf("global url = %q", out.Global.URL)
	}
	// 未显式配置的模块补默认 global，前端读到的结构是完整的。
	for _, m := range Modules() {
		ov, ok := out.Modules[m]
		if !ok {
			t.Fatalf("module %s missing after normalize", m)
		}
		if ov.Mode != ModeGlobal && m != "tool_download" && m != "intel" {
			t.Fatalf("module %s mode = %q, want global", m, ov.Mode)
		}
	}
	if out.Modules["tool_download"].Mode != ModeCustom {
		t.Fatalf("tool_download mode = %q", out.Modules["tool_download"].Mode)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"全局启用但 URL 为空", Config{Global: ProxyEntry{Enabled: true}}},
		{"全局 scheme 不支持", Config{Global: ProxyEntry{Enabled: true, URL: "ftp://1.2.3.4:21"}}},
		{"全局 URL 缺 host", Config{Global: ProxyEntry{Enabled: true, URL: "http:///path"}}},
		{"custom 未填 URL", Config{Modules: map[string]Override{"intel": {Mode: ModeCustom}}}},
		{"custom URL scheme 不支持", Config{Modules: map[string]Override{"intel": {Mode: ModeCustom, URL: "ftp://x"}}}},
		{"未知模块", Config{Modules: map[string]Override{"nope": {Mode: ModeDirect}}}},
		{"非法 mode", Config{Modules: map[string]Override{"intel": {Mode: "bypass"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Validate(tc.cfg); err == nil {
				t.Fatalf("want error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------- ProxyFor

func newTestResolver(t *testing.T, cfg *Config) *Resolver {
	t.Helper()
	fs := &fakeStore{}
	if cfg != nil {
		fs.data = map[string][]byte{SettingsKey: cfgJSON(t, *cfg)}
	}
	return NewResolver(fs)
}

func TestProxyForModuleModes(t *testing.T) {
	cfg := &Config{
		Global: ProxyEntry{Enabled: true, URL: "http://global:7890"},
		Modules: map[string]Override{
			"tool_download": {Mode: ModeCustom, URL: "socks5://u:p@td:1080"},
			"intel":         {Mode: ModeDirect},
		},
	}
	r := newTestResolver(t, cfg)
	ctx := context.Background()

	if got, err := r.ProxyFor(ctx, "tool_download"); err != nil || got == nil || got.Scheme != "socks5" {
		t.Fatalf("custom: %v %v", got, err)
	}
	if got, _ := r.ProxyFor(ctx, "tool_download"); got.Host != "td:1080" || got.User.Username() != "u" {
		t.Fatalf("custom host/user = %q %q", got.Host, got.User.Username())
	}
	if got, err := r.ProxyFor(ctx, "intel"); err != nil || got != nil {
		t.Fatalf("direct: %v %v", got, err)
	}
	if got, err := r.ProxyFor(ctx, "notify"); err != nil || got == nil || got.Host != "global:7890" {
		t.Fatalf("follow global: %v %v", got, err)
	}
}

func TestProxyForGlobalDisabledMeansEnv(t *testing.T) {
	r := newTestResolver(t, &Config{})
	got, err := r.ProxyFor(context.Background(), "recon")
	if err != nil || got != nil {
		t.Fatalf("global off 应返回 nil（跟随环境变量）: %v %v", got, err)
	}
}

func TestProxyForUnknownModule(t *testing.T) {
	r := newTestResolver(t, &Config{})
	if _, err := r.ProxyFor(context.Background(), "typo"); err == nil {
		t.Fatalf("未知模块应报错")
	}
}

func TestProxyForWithoutStore(t *testing.T) {
	r := NewResolver(nil)
	got, err := r.ProxyFor(context.Background(), "intel")
	if err != nil || got != nil {
		t.Fatalf("无存储应视为未配置: %v %v", got, err)
	}
}

func TestProxyForCustomEmptyURL(t *testing.T) {
	cfg := &Config{Modules: map[string]Override{"intel": {Mode: ModeCustom, URL: "  "}}}
	r := newTestResolver(t, cfg)
	if _, err := r.ProxyFor(context.Background(), "intel"); err == nil {
		t.Fatalf("custom 空 URL 应报错")
	}
}

// ---------------------------------------------------------------- ProxyFuncFor

func TestProxyFuncFor(t *testing.T) {
	cfg := &Config{
		Global:  ProxyEntry{Enabled: true, URL: "http://global:7890"},
		Modules: map[string]Override{"intel": {Mode: ModeDirect}},
	}
	r := newTestResolver(t, cfg)

	// custom/global 解析到代理 → 恒定返回该代理。
	fn := r.ProxyFuncFor(context.Background(), "notify")
	u, err := fn(&http.Request{URL: mustURL(t, "https://api.github.com/x")})
	if err != nil || u == nil || u.Host != "global:7890" {
		t.Fatalf("proxy fn: %v %v", u, err)
	}

	// direct → 返回 nil 函数，即 Transport.Proxy = nil（真直连，忽略环境变量）。
	direct := r.ProxyFuncFor(context.Background(), "intel")
	if direct != nil {
		t.Fatalf("direct 应返回 nil 函数")
	}

	// 全局未开启 → 跟随环境变量（保持既有行为）。
	env := r.ProxyFuncFor(context.Background(), "recon")
	if env == nil {
		t.Fatalf("global off 应回退 ProxyFromEnvironment")
	}
}

// ---------------------------------------------------------------- 缓存与热更

func TestModeFor(t *testing.T) {
	cfg := &Config{
		Global:  ProxyEntry{Enabled: true, URL: "http://global:7890"},
		Modules: map[string]Override{"intel": {Mode: ModeDirect}},
	}
	r := newTestResolver(t, cfg)
	if got := r.ModeFor(context.Background(), "intel"); got != ModeDirect {
		t.Fatalf("intel mode = %q", got)
	}
	if got := r.ModeFor(context.Background(), "notify"); got != ModeGlobal {
		t.Fatalf("notify mode = %q", got)
	}
	// 未知模块回退 global，不报错（调用方据此走环境变量语义）。
	if got := r.ModeFor(context.Background(), "typo"); got != ModeGlobal {
		t.Fatalf("typo mode = %q", got)
	}
	// 存储未注入时同样视为跟随全局。
	empty := NewResolver(nil)
	if got := empty.ModeFor(context.Background(), "intel"); got != ModeGlobal {
		t.Fatalf("no-store mode = %q", got)
	}
}

func TestResolverCachesUntilInvalidate(t *testing.T) {
	fs := &fakeStore{data: map[string][]byte{SettingsKey: cfgJSON(t, Config{
		Global: ProxyEntry{Enabled: true, URL: "http://v1:1"},
	})}}
	r := NewResolver(fs)
	ctx := context.Background()
	if u, _ := r.ProxyFor(ctx, "intel"); u.Host != "v1:1" {
		t.Fatalf("first read: %v", u)
	}
	first := fs.getN

	fs.data[SettingsKey] = cfgJSON(t, Config{Global: ProxyEntry{Enabled: true, URL: "http://v2:2"}})
	if u, _ := r.ProxyFor(ctx, "intel"); u.Host != "v1:1" {
		t.Fatalf("TTL 内应命中缓存: %v", u)
	}
	r.Invalidate()
	if u, _ := r.ProxyFor(ctx, "intel"); u.Host != "v2:2" {
		t.Fatalf("失效后应读到新值: %v", u)
	}
	if fs.getN == first {
		t.Fatalf("失效后应重新读存储")
	}
}

func TestResolverStoreErrorKeepsLastGood(t *testing.T) {
	fs := &fakeStore{data: map[string][]byte{SettingsKey: cfgJSON(t, Config{
		Global: ProxyEntry{Enabled: true, URL: "http://good:1"},
	})}}
	r := NewResolver(fs)
	ctx := context.Background()
	if u, _ := r.ProxyFor(ctx, "intel"); u.Host != "good:1" {
		t.Fatalf("initial: %v", u)
	}
	fs.miss = true // 模拟存储抖动
	r.Invalidate()
	if u, _ := r.ProxyFor(ctx, "intel"); u == nil || u.Host != "good:1" {
		t.Fatalf("存储读不到时应沿用上次配置: %v", u)
	}
}
