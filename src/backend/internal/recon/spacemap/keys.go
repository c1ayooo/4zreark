// keys.go 引擎 API Key 的存储与解析:环境变量优先(容器部署友好),settings 表
// 兜底(UI 可配)。存储/读取走注入的 KV 接口,db.DB 天然满足;掩码回显供 HTTP 层。
package spacemap

import (
	"fmt"
	"os"
	"strings"
)

// KV 是 key 存储的最小接口(db.DB 满足)。
type KV interface {
	GetSetting(key string) (value string, ok bool, err error)
	SetSetting(key, value string) error
}

// SettingsKey 某引擎 API Key 的 settings 键。
func SettingsKey(provider string) string {
	return "spacemap.key." + normalizeProvider(provider)
}

// BaseURLSettingsKey 某引擎自定义端点的 settings 键。
func BaseURLSettingsKey(provider string) string {
	return "spacemap.baseurl." + normalizeProvider(provider)
}

// ResolveKey env 优先,settings 兜底;均未配置返回空。
func ResolveKey(kv KV, provider string) string {
	provider = normalizeProvider(provider)
	if env := EnvKeyNames[provider]; env != "" {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	if kv == nil {
		return ""
	}
	if v, ok, err := kv.GetSetting(SettingsKey(provider)); err == nil && ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// ResolveBaseURL 自定义端点(空=内置默认)。
func ResolveBaseURL(kv KV, provider string) string {
	provider = normalizeProvider(provider)
	if kv == nil {
		return ""
	}
	if v, ok, err := kv.GetSetting(BaseURLSettingsKey(provider)); err == nil && ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// KeyFromEnv 该引擎的 key 是否来自环境变量(回显时标注"来自环境变量,页面修改无效")。
func KeyFromEnv(provider string) bool {
	if env := EnvKeyNames[normalizeProvider(provider)]; env != "" {
		return strings.TrimSpace(os.Getenv(env)) != ""
	}
	return false
}

// Mask 掩码回显:保留前 4 后 2,中间打点;过短的完全打码。
func Mask(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", 6) + key[len(key)-2:]
}

// ---------- 域名查询语法(移植自 4zreco space_batch_tools 的语法表) ----------

// ValidProvider 是否为受支持的引擎名(归一化后非空)。
func ValidProvider(provider string) bool { return normalizeProvider(provider) != "" }

// DomainQuery 某引擎按域名查资产的查询语句。
// fofa/zoomeye: domain="example.com"；quake: domain:"example.com"；
// hunter: domain.suffix="example.com"；shodan: hostname:example.com
func DomainQuery(provider, domain string) string {
	switch normalizeProvider(provider) {
	case "quake":
		return fmt.Sprintf("domain:%q", domain)
	case "shodan":
		return "hostname:" + domain
	case "hunter":
		return fmt.Sprintf("domain.suffix=%q", domain)
	default: // fofa / zoomeye
		return fmt.Sprintf("domain=%q", domain)
	}
}

// DomainQueryTemplate 语法模板展示({d} 为域名占位)。
func DomainQueryTemplate(provider string) string {
	return DomainQuery(provider, "{d}")
}

// SummarizeRow 把一行引擎原始结果压成单行摘要(工具输出样本用)。
func SummarizeRow(row map[string]interface{}) string {
	host := firstNonEmpty(
		rowStringValue(row, "host"),
		rowStringValue(row, "domain"),
		rowStringValue(row, "ip"), rowStringValue(row, "ip_str"),
	)
	port := rowIntValue(row, "port")
	title := rowStringValue(row, "title", "web_title", "service.http.title", "http.title")
	parts := make([]string, 0, 3)
	if host != "" {
		parts = append(parts, host)
	}
	if port > 0 {
		parts = append(parts, fmt.Sprintf("port %d", port))
	}
	if title != "" {
		if len([]rune(title)) > 60 {
			title = string([]rune(title)[:60]) + "…"
		}
		parts = append(parts, title)
	}
	if len(parts) == 0 {
		return "(空行)"
	}
	return strings.Join(parts, " | ")
}
