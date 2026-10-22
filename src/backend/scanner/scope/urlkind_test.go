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
