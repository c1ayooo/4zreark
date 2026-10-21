package service

import (
	"reflect"
	"testing"
)

func TestProjectRootDomains(t *testing.T) {
	got := projectRootDomains([]string{
		"meituan.com",
		"api.meituan.com",
		"https://waimai.meituan.com:443/path?q=1",
		"*.vip.meituan.com.",
		"101.50.8.46",
		"localhost",
		"MEITUAN.COM",
	})
	want := []string{"meituan.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectRootDomains = %v, want %v", got, want)
	}
}

func TestNormalizeHostName(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com:8443/a/b": "api.example.com",
		"API.Example.COM.":                 "api.example.com",
		"*.example.com":                    "example.com",
		"[2001:db8::1]:443":                "2001:db8::1",
		"example.com:443":                  "example.com",
	}
	for in, want := range cases {
		if got := normalizeHostName(in); got != want {
			t.Errorf("normalizeHostName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanCruiseTargets(t *testing.T) {
	got := cleanCruiseTargets([]string{" a.com ", "", "  ", "b.com"})
	want := []string{"a.com", "b.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanCruiseTargets = %v, want %v", got, want)
	}
}
