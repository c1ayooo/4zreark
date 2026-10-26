package subdomain

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestEngineKeyTaskLevelPriority(t *testing.T) {
	s := &ActiveScanner{config: &ActiveScannerConfig{EngineKeys: map[string]string{
		"fofa":   "task-fofa",
		"hunter": "task-hunter",
		"quake":  "task-quake",
	}}}
	for provider, want := range map[string]string{
		"fofa":   "task-fofa",
		"hunter": "task-hunter",
		"quake":  "task-quake",
	} {
		if got := s.engineKey(provider); got != want {
			t.Fatalf("engineKey(%q)=%q，期望 %q", provider, got, want)
		}
	}
	// 未配置的引擎回落到全局配置（测试进程未加载 config -> 空）
	if got := s.engineKey("zoomeye"); got != "" {
		t.Fatalf("未配置引擎应返回空，实际 %q", got)
	}
}

// ZRE_LIVE=1 go test ./scanner/subdomain -run TestLiveBrute -v
func TestLiveBrute(t *testing.T) {
	if os.Getenv("ZRE_LIVE") == "" {
		t.Skip("set ZRE_LIVE=1 to run DNS live test")
	}
	s := NewDomainScanner(32)
	s.Resolvers = []string{"223.5.5.5:53", "119.29.29.29:53"}
	s.Timeout = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res := s.BruteSubdomains(ctx, "example.com", []string{"www", "mail", "api", "blog"})
	t.Logf("found=%d probed=%d duration=%s", res.Found, res.TotalChecked, res.Duration)
	for _, sub := range res.Subdomains {
		t.Logf("  %s ips=%v cname=%v", sub.FullDomain, sub.IPs, sub.CNAMEs)
	}
	if res.Found == 0 {
		t.Fatal("example.com 至少应命中 www（DNS 或网络不可用）")
	}
	for _, sub := range res.Subdomains {
		if len(sub.IPs) == 0 {
			t.Fatalf("命中的子域应有 IP: %+v", sub)
		}
	}
}
