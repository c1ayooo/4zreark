package enterprise

import (
	"fmt"
	"strings"
)

// ProviderKind 上游数据源类型。与 datasource_sessions.provider 一致。
type ProviderKind struct {
	Name      string // 会话 provider 标识
	Label     string // 展示名
	Auth      string // cookie / token / pending（待接入校准）
	Available bool   // false = 端点未校准，构造时返回明确错误
	Hint      string // 配置提示（前端展示用）
}

// Registry enscan_go（MIT）支持的数据源全集（对照源码 internal/* 逐个移植）。
// qcc（fork 未含实现，上游强反爬+字段加密）、xiaolanben（fork 未含实现）
// 标记 pending，使用时返回明确错误而不是假请求。
var Registry = []ProviderKind{
	{Name: "aqc", Label: "爱企查", Auth: "cookie", Available: true, Hint: "网页版 Cookie（含 BIDUID 等全量）"},
	{Name: "tyc", Label: "天眼查", Auth: "cookie", Available: true, Hint: "网页版登录 Cookie，或请求头 x-auth-token 值（auth_token 自动提取）"},
	{Name: "kuaicha", Label: "快查", Auth: "cookie", Available: true, Hint: "kuaicha365.com 网页版登录 Cookie"},
	{Name: "fengniao", Label: "风鸟", Auth: "account", Available: true, Hint: "账号密码自动登录（密码登录无验证码）或网页版 Cookie"},
	{Name: "qcc", Label: "企查查", Auth: "cookie", Available: true, Hint: "网页版 Cookie（需含 QCCSESSID + acw_tc；走 SSR 页面解析，含注册资本）"},
	{Name: "xiaolanben", Label: "小蓝本", Auth: "account", Available: true, Hint: "账号密码登录（RSA 加密）；查询经平台内嵌无头浏览器承载上游签名"},
}

// NewProvider 工厂：按会话 provider 类型构造对应 adapter。
// cfg 为 datasource vault 中的会话配置（cookie/proxy_url 等）。
func NewProvider(provider string, cfg map[string]string, proxyURL string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aqc":
		return NewAqcProvider(cfg["cookie"], effectiveProxy(cfg, proxyURL))
	case "tyc":
		return NewTycProvider(cfg["cookie"], effectiveProxy(cfg, proxyURL))
	case "kuaicha":
		return NewKuaichaProvider(cfg["cookie"], effectiveProxy(cfg, proxyURL))
	case "fengniao":
		// 风鸟支持两种会话形态：账号密码自动登录（username/password）或手动 Cookie。
		if cfg["username"] != "" && cfg["password"] != "" {
			return NewFengniaoAccountProvider(cfg["username"], cfg["password"], effectiveProxy(cfg, proxyURL))
		}
		return NewFengniaoProvider(cfg["cookie"], effectiveProxy(cfg, proxyURL))
	case "qcc":
		return NewQccProvider(cfg["cookie"], effectiveProxy(cfg, proxyURL))
	case "xiaolanben":
		return NewXiaolanbenProvider(cfg["username"], cfg["password"], effectiveProxy(cfg, proxyURL))
	default:
		return nil, fmt.Errorf("不支持的数据源类型 %q（支持：aqc/tyc/kuaicha/fengniao/qcc/xiaolanben）", provider)
	}
}

// effectiveProxy 会话级代理覆盖 > 全局代理。
func effectiveProxy(cfg map[string]string, global string) string {
	if v := strings.TrimSpace(cfg["proxy_url"]); v != "" {
		return v
	}
	return global
}
