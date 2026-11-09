package useragent

import (
	"context"
	"net/http"
	"testing"
)

func TestForSiteDeterministic(t *testing.T) {
	a := ForSite("seed-a", "api.example.com:443")
	b := ForSite("seed-a", "api.example.com:443")
	if a != b {
		t.Fatalf("同一 seed+站点必须得到同一会话: %+v != %+v", a, b)
	}
	if a.UserAgent == "" || a.AcceptLanguage == "" {
		t.Fatalf("会话字段不能为空: %+v", a)
	}

	other := ForSite("seed-b", "api.example.com:443")
	if other == a {
		// seed 不同通常应得到不同索引；池只有 6 个，碰撞概率存在，
		// 这里只记录不失败，避免测试变成概率性失败。
		t.Logf("不同 seed 命中同一 UA（允许的低概率碰撞）: %s", a.UserAgent)
	}
}

func TestForSiteDifferentHosts(t *testing.T) {
	seen := map[string]bool{}
	for _, host := range []string{
		"a.example.com", "b.example.com", "c.example.com",
		"d.example.com", "e.example.com", "f.example.com",
	} {
		seen[ForSite("seed", host).UserAgent] = true
	}
	if len(seen) < 2 {
		t.Fatalf("不同站点至少应出现 2 种 UA，实际 %d", len(seen))
	}
}

func TestApplyUsesContextSeed(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithSeed(context.Background(), "task-seed")
	req = req.WithContext(ctx)
	Apply(req)

	want := ForSite("task-seed", "api.example.com").UserAgent
	if got := req.Header.Get("User-Agent"); got != want {
		t.Fatalf("Apply UA = %q, want %q", got, want)
	}
	if req.Header.Get("Accept-Language") == "" {
		t.Fatal("Apply 应同时设置配套 Accept-Language")
	}
}

func TestApplyWithoutSeedStillStable(t *testing.T) {
	req1, _ := http.NewRequest(http.MethodGet, "https://same.example.com/a", nil)
	req2, _ := http.NewRequest(http.MethodGet, "https://same.example.com/b", nil)
	Apply(req1)
	Apply(req2)
	if req1.Header.Get("User-Agent") != req2.Header.Get("User-Agent") {
		t.Fatalf("无 seed 时同一站也必须稳定: %q != %q",
			req1.Header.Get("User-Agent"), req2.Header.Get("User-Agent"))
	}
}

func TestSessionOverridesSeed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	session := Session{UserAgent: "custom-agent", AcceptLanguage: "en-US"}
	req = req.WithContext(WithSession(WithSeed(context.Background(), "seed"), session))
	Apply(req)
	if got := req.Header.Get("User-Agent"); got != "custom-agent" {
		t.Fatalf("显式会话应优先，got %q", got)
	}
}

func TestDeriveSeedStableAndProjectScoped(t *testing.T) {
	a := DeriveSeed("secret", 1)
	b := DeriveSeed("secret", 1)
	if a != b || a == "" {
		t.Fatalf("同项目 seed 必须稳定: %q %q", a, b)
	}
	if c := DeriveSeed("secret", 2); c == a {
		t.Fatal("不同项目 seed 不应相同")
	}
	if d := DeriveSeed("", 1); d == "" {
		t.Fatal("密钥缺失时也应有可复现的 seed")
	}
}
