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
