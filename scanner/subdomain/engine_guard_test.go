package subdomain

import "testing"

func TestEngineQueryGuardDedupByBaseDomain(t *testing.T) {
	g := NewEngineQueryGuard(10)
	// 同一注册域的多个子域：只有第一次放行，其余按去重拒绝
	if ok, _ := g.Allow("fofa", "www.example.com"); !ok {
		t.Fatal("first query should pass")
	}
	if ok, reason := g.Allow("fofa", "api.example.com"); ok {
		t.Fatal("same base domain should be deduped")
	} else if reason == "" {
		t.Fatal("reason should explain the skip")
	}
	// 不同注册域放行
	if ok, _ := g.Allow("fofa", "other.org"); !ok {
		t.Fatal("different base domain should pass")
	}
	// 引擎之间独立
	if ok, _ := g.Allow("quake", "www.example.com"); !ok {
		t.Fatal("per-engine budget should be independent")
	}
}

func TestEngineQueryGuardCap(t *testing.T) {
	g := NewEngineQueryGuard(2)
	domains := []string{"a.com", "b.com", "c.com", "d.com"}
	passed := 0
	for _, d := range domains {
		if ok, _ := g.Allow("fofa", d); ok {
			passed++
		}
	}
	if passed != 2 {
		t.Fatalf("cap=2 but passed %d", passed)
	}
	if ok, _ := g.Allow("fofa", "e.com"); ok {
		t.Fatal("should be capped")
	}
	// 其他引擎不受影响
	if ok, _ := g.Allow("shodan", "a.com"); !ok {
		t.Fatal("other engine budget should be independent")
	}
}

func TestEngineQueryGuardNilAllowsAll(t *testing.T) {
	var g *EngineQueryGuard
	if ok, _ := g.Allow("fofa", "a.com"); !ok {
		t.Fatal("nil guard should allow all (tests/legacy)")
	}
}

func TestBaseDomain(t *testing.T) {
	cases := map[string]string{
		"WWW.Example.COM.":  "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"203.0.113.9":       "203.0.113.9",
		"":                  "",
	}
	for in, want := range cases {
		if got := BaseDomain(in); got != want {
			t.Fatalf("BaseDomain(%q)=%q want %q", in, got, want)
		}
	}
}
