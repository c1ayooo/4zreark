// Package evidenceguard 提供证据引文校验的纯函数部分。
//
// 来源：4zreco internal/evidenceguard。4zreco 的完整实现还绑定 tool_executions /
// evidence 表；4zreark 只搬「引文归一 + 子串判定」这两个与数据库无关的判定面，
// 供报告/漏洞证据体检使用。
package evidenceguard

import (
	"regexp"
	"strings"
)

var whitespaceRun = regexp.MustCompile(`\s+`)

// NormalizeForQuoteCheck 引文归一：连续空白折叠为单空格 + 去首尾，保留大小写。
func NormalizeForQuoteCheck(s string) string {
	return strings.TrimSpace(whitespaceRun.ReplaceAllString(s, " "))
}

// QuoteFoundInText 判断引文（归一后）是否为文本的子串。
func QuoteFoundInText(quote, text string) bool {
	q := NormalizeForQuoteCheck(quote)
	if q == "" {
		return false
	}
	return strings.Contains(NormalizeForQuoteCheck(text), q)
}
