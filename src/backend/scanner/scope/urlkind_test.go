package scope

import "testing"

func TestIsStaticAssetKeepsJS(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/static/app.js", false},
		{"https://example.com/static/app.mjs", false},
		{"https://example.com/api/v1/users", false},
		{"https://example.com/static/app.css", true},
		{"https://example.com/static/logo.png", true},
		{"https://example.com/static/font.woff2", true},
		{"https://example.com/static/app.js.map", true},
	}
	for _, tc := range cases {
		if got := IsStaticAsset(tc.url); got != tc.want {
			t.Errorf("IsStaticAsset(%q) = %v，期望 %v", tc.url, got, tc.want)
		}
	}
}

func TestIsNoisyCrawlerURL(t *testing.T) {
	noisy := []string{
		"https://www.meituan.com/docker/opt/meituan/appdatas/nest/function/src/locales",
		"https://www.meituan.com/%5Cu003e%5Cu003c/div%5Cu003e",
		"https://www.meituan.com/" + string(make([]byte, 2100)),
	}
	for _, u := range noisy {
		if !IsNoisyCrawlerURL(u) {
			t.Errorf("应判为噪声: %s", u)
		}
	}
	for _, u := range []string{"https://www.meituan.com/api/v1/order", "https://developer.meituan.com/en-US/docs/biz"} {
		if IsNoisyCrawlerURL(u) {
			t.Errorf("不应判为噪声: %s", u)
		}
	}
}

func TestInterfaceReason(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		method      string
		contentType string
		attribute   string
		want        string
	}{
		{"api prefix", "https://example.com/api/v1/users", "GET", "text/html", "href", "path"},
		{"no api prefix path", "https://example.com/gateway/order/list", "GET", "", "", "path"},
		{"query string", "https://example.com/category/allData?type=1", "GET", "", "", "query"},
		{"post method", "https://example.com/submit", "POST", "", "", "method"},
		{"json response", "https://example.com/report", "GET", "application/json; charset=utf-8", "", "content_type"},
		{"jsluice fetch", "https://career.example.com/category/allData", "GET", "", "jsluice-fetch", "jsluice"},
		{"plain page", "https://example.com/about", "GET", "text/html", "href", ""},
		{"segment must be exact", "https://example.com/restaurant/1", "GET", "", "", ""},
	}
	for _, tc := range cases {
		if got := InterfaceReason(tc.url, tc.method, tc.contentType, tc.attribute); got != tc.want {
			t.Errorf("%s: InterfaceReason(%q) = %q，期望 %q", tc.name, tc.url, got, tc.want)
		}
	}
}
