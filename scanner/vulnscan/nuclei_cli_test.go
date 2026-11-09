package vulnscan

import (
	"strings"
	"testing"
)

func TestNucleiBuildArgsInjectsStationUA(t *testing.T) {
	s := &NucleiCLIScanner{concurrency: 10, rateLimit: 100}
	args := s.buildArgs([]string{"https://a.example.com/login"}, &NucleiScanConfig{})

	ua := ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-H" && strings.HasPrefix(args[i+1], "User-Agent: ") {
			ua = strings.TrimPrefix(args[i+1], "User-Agent: ")
		}
	}
	if ua == "" {
		t.Fatal("nuclei buildArgs 未注入 User-Agent")
	}
	if strings.Contains(strings.ToLower(ua), "nuclei") || strings.Contains(ua, "Go-http-client") {
		t.Fatalf("UA 暴露了工具身份: %q", ua)
	}
}

func TestNucleiBuildArgsKeepsExplicitUA(t *testing.T) {
	s := &NucleiCLIScanner{concurrency: 10, rateLimit: 100}
	args := s.buildArgs([]string{"https://a.example.com"}, &NucleiScanConfig{UserAgent: "custom-ua"})
	found := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-H" && args[i+1] == "User-Agent: custom-ua" {
			found = true
		}
	}
	if !found {
		t.Fatal("显式 UserAgent 未原样透传")
	}
}
