package webscan

import "testing"

func TestRadInScope(t *testing.T) {
	cases := []struct {
		target, candidate string
		want              bool
	}{
		{"https://www.example.com", "https://api.example.com/x", true},
		{"https://www.example.com", "http://example.com/", true},
		{"https://www.example.com", "https://evil.com/x", false},
		{"https://example.com", "https://notexample.com", false},
		{"https://10.0.0.1", "http://10.0.0.1/admin", true},
		{"https://10.0.0.1", "http://10.0.0.2/admin", false},
		{"not a url", "https://example.com", false},
	}
	for _, tc := range cases {
		if got := radInScope(tc.target, tc.candidate); got != tc.want {
			t.Errorf("radInScope(%q, %q)=%v，期望 %v", tc.target, tc.candidate, got, tc.want)
		}
	}
}

func TestRadParseOutputFiltersOffScope(t *testing.T) {
	r := &RadScanner{}
	res := r.parseOutput("https://www.example.com", "https://api.example.com/a\nhttps://evil.com/b\n", &RadResult{
		Target: "https://www.example.com",
	})
	if len(res.URLs) != 1 || res.URLs[0].URL != "https://api.example.com/a" {
		t.Fatalf("解析结果应只保留注册域内 URL: %+v", res.URLs)
	}
}
