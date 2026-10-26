package service

import (
	"context"
	"testing"
	"time"
)

func TestBaseDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://www.example.com/login?x=1", "example.com"},
		{"api.example.com:8443", "example.com"},
		{"example.com", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		{"127.0.0.1", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := baseDomain(c.in); got != c.want {
			t.Fatalf("baseDomain(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestBoolDefaultTrue(t *testing.T) {
	if !boolDefaultTrue(nil) {
		t.Fatal("nil 应默认开启")
	}
	yes, no := true, false
	if !boolDefaultTrue(&yes) || boolDefaultTrue(&no) {
		t.Fatal("显式开关未生效")
	}
}

func TestResolveCandidatesFiltersDeadNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := resolveCandidates(ctx, []string{"localhost", "zre-does-not-exist.invalid"}, 4)
	if len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("应只保留可解析的候选，实际 %v", got)
	}
}
