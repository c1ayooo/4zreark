package enterprise

import (
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
)

// 各 adapter 共用的解析辅助。

var reTag = regexp.MustCompile(`<[^>]+>`)

// stripHTML 去除上游返回文本里的高亮标签（<em> 等）与空白。
func stripHTML(s string) string {
	return strings.TrimSpace(reTag.ReplaceAllString(s, ""))
}

// firstExistingString 按优先级取第一个存在的字符串字段（各平台字段名漂移容错）。
func firstExistingString(item gjson.Result, paths ...string) string {
	for _, p := range paths {
		if v := item.Get(p); v.Exists() && v.String() != "" {
			return v.String()
		}
	}
	return ""
}

// normalizeDomain 去协议/路径/端口，小写化，非法输入返回空。
func normalizeDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	if i := strings.IndexAny(v, "/:?#"); i >= 0 {
		v = v[:i]
	}
	if v == "" || len(v) > 253 || !strings.Contains(v, ".") {
		return ""
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return ""
	}
	return v
}
