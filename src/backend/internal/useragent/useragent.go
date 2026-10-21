// Package useragent 提供统一的浏览器 UA，避免扫描/探测请求暴露工具身份。
package useragent

import (
	"math/rand/v2"
	"net/http"
	"strings"
)

// Desktop 是常见桌面浏览器 UA；每次随机取一个，降低固定指纹。
var Desktop = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
}

// Mobile 是手机浏览器 UA；桌面 UA 被 403/406/429 挡住时回退使用。
var Mobile = []string{
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
}

func Pick() string       { return Desktop[rand.IntN(len(Desktop))] }
func PickMobile() string { return Mobile[rand.IntN(len(Mobile))] }

// Apply 设置桌面浏览器 UA。
func Apply(req *http.Request) { req.Header.Set("User-Agent", Pick()) }

// ApplyMobile 设置手机浏览器 UA。
func ApplyMobile(req *http.Request) { req.Header.Set("User-Agent", PickMobile()) }

// Transport 兜底覆盖工具型 UA；浏览器型 UA（含 Chrome/Safari/Firefox/Edg）
// 保持不变，避免覆盖调用方刻意设置的版本。
type Transport struct{ Base http.RoundTripper }

func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	clone := req.Clone(req.Context())
	ua := strings.ToLower(clone.Header.Get("User-Agent"))
	if ua == "" || !looksLikeBrowser(ua) {
		clone.Header.Set("User-Agent", Pick())
	}
	return base.RoundTrip(clone)
}

func looksLikeBrowser(ua string) bool {
	return strings.Contains(ua, "chrome/") || strings.Contains(ua, "safari/") ||
		strings.Contains(ua, "firefox/") || strings.Contains(ua, "edg/") ||
		strings.Contains(ua, "gecko/")
}
