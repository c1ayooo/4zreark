package service

import "testing"

func TestCleanEnterpriseName(t *testing.T) {
	cases := map[string]string{
		"美团src":      "美团",
		"美团项目":       "美团",
		"测试":         "测试",
		"  AcmeSRC ": "Acme",
		"":           "",
	}
	for in, want := range cases {
		if got := CleanEnterpriseName(in); got != want {
			t.Errorf("CleanEnterpriseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeAutoDomain(t *testing.T) {
	cases := map[string]string{
		"https://WWW.Example.com/path": "www.example.com",
		"example.com:8443":             "example.com",
		"example.com.":                 "example.com",
		"10.0.0.1":                     "",
		"not a domain":                 "",
		"":                             "",
	}
	for in, want := range cases {
		if got := normalizeAutoDomain(in); got != want {
			t.Errorf("normalizeAutoDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
