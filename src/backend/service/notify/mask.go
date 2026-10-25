package notify

import (
	"os"
	"regexp"
	"strings"
)

// 通知内容脱敏：密码/令牌/AK/私钥/手机号/身份证。
// 通知会经过 IM、邮件与 Webhook，默认不把明文凭据送出去。

var (
	reSecretKV = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)`)
	reBearer   = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	reAWSKey   = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	rePrivate  = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	rePhoneCN  = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	reIDCard   = regexp.MustCompile(`\b\d{17}[\dXx]\b`)
)

// MaskSensitive 返回脱敏后的文本。
func MaskSensitive(s string) string {
	if s == "" {
		return s
	}
	s = rePrivate.ReplaceAllString(s, "[PRIVATE KEY REDACTED]")
	s = reBearer.ReplaceAllString(s, "Bearer ***")
	s = reAWSKey.ReplaceAllString(s, "AKIA****************")
	s = reSecretKV.ReplaceAllString(s, "$1=***")
	s = rePhoneCN.ReplaceAllStringFunc(s, func(v string) string {
		if len(v) != 11 {
			return "***"
		}
		return v[:3] + "****" + v[7:]
	})
	s = reIDCard.ReplaceAllStringFunc(s, func(v string) string {
		if len(v) != 18 {
			return "***"
		}
		return v[:6] + "********" + v[14:]
	})
	return s
}

// NotifyLevelAllowed 按 ZRE_NOTIFY_MIN_LEVEL（info/warning/critical，默认 info）
// 过滤通知级别；未知值按 info 处理。
func NotifyLevelAllowed(level NotifyLevel) bool {
	min := strings.ToLower(strings.TrimSpace(os.Getenv("ZRE_NOTIFY_MIN_LEVEL")))
	if min == "" {
		return true
	}
	return levelRank(level) >= levelRank(NotifyLevel(min))
}

// ChannelLevelAllowed 判断消息级别是否达到渠道门槛。min 为空或非法 = 全收。
// 分级路由靠它：比如 critical 渠道只收 critical，warning 渠道收 warning 及以上。
func ChannelLevelAllowed(level, min NotifyLevel) bool {
	min = NotifyLevel(strings.ToLower(strings.TrimSpace(string(min))))
	if min == "" {
		return true
	}
	return levelRank(level) >= levelRank(min)
}

func levelRank(l NotifyLevel) int {
	switch l {
	case NotifyLevelCritical:
		return 2
	case NotifyLevelWarning:
		return 1
	default:
		return 0
	}
}

func MaskMessage(msg *NotifyMessage) {
	if msg == nil {
		return
	}
	msg.Title = MaskSensitive(msg.Title)
	msg.Content = MaskSensitive(msg.Content)
	if msg.Extra != nil {
		for k, v := range msg.Extra {
			switch x := v.(type) {
			case string:
				msg.Extra[k] = MaskSensitive(x)
			case []string:
				out := make([]string, len(x))
				for i, s := range x {
					out[i] = MaskSensitive(s)
				}
				msg.Extra[k] = out
			}
		}
	}
	msg.Source = MaskSensitive(strings.TrimSpace(msg.Source))
}
