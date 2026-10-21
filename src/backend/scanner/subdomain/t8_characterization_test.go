package subdomain

import (
	"net/http"
	"testing"
)

// T8 特性测试：锁定子域/指纹/CDN 判定中不依赖网络的那部分对外行为。
// 阶段 B 用 reconkit 替换旧实现时，这些断言是回退判据。

func TestT8ParseWordlist(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"换行分隔与去重", "www\napi\nwww\n\n mail \r\n", []string{"www", "api", "mail"}},
		{"逗号分隔", "www, api,www, db", []string{"www", "api", "db"}},
		{"空输入", "", nil},
		{"单值", "only", []string{"only"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseWordlist(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("ParseWordlist(%q)=%v，期望 %v", c.in, got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("ParseWordlist(%q)=%v，期望 %v", c.in, got, c.want)
				}
			}
		})
	}
}

func TestT8UniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"a", "", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("uniqueStrings 结果不符: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("uniqueStrings 结果不符: %v", got)
		}
	}
}

func TestT8DetectFingerprints(t *testing.T) {
	body := `<script src="/wp-content/app.js"></script><div ng-version="17">jquery</div>`
	headers := http.Header{"Set-Cookie": []string{"PHPSESSID=abc"}}

	got := detectFingerprints(body, headers)
	want := map[string]bool{"Angular": true, "jQuery": true, "PHP": true, "WordPress": true}
	if len(got) != len(want) {
		t.Fatalf("指纹结论不符: %v，期望 %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("出现预期外指纹 %q（完整结果 %v）", name, got)
		}
	}
}

func TestT8CheckCDNByIP(t *testing.T) {
	cases := map[string]string{
		"104.16.1.1":    "Cloudflare",
		"103.21.244.10": "Cloudflare",
		"192.0.2.10":    "",
		"8.8.8.8":       "",
	}
	for ip, want := range cases {
		if got := checkCDNByIP(ip); got != want {
			t.Fatalf("checkCDNByIP(%q)=%q，期望 %q", ip, got, want)
		}
	}
}

func TestT8DetectCDNClassification(t *testing.T) {
	s := &DomainScanner{}

	if ok, provider := s.detectCDN([]string{"static.cloudflare.net"}, nil); !ok || provider != "Cloudflare" {
		t.Fatalf("CNAME 判定不符: ok=%v provider=%q", ok, provider)
	}
	if ok, provider := s.detectCDN(nil, []string{"104.16.5.5"}); !ok || provider != "Cloudflare" {
		t.Fatalf("IP 判定不符: ok=%v provider=%q", ok, provider)
	}
	if ok, provider := s.detectCDN([]string{"www.example.com"}, []string{"192.0.2.10"}); ok || provider != "" {
		t.Fatalf("非 CDN 应返回 false/空，实际 ok=%v provider=%q", ok, provider)
	}
}

func TestT8IsWildcardIP(t *testing.T) {
	s := &DomainScanner{WildcardIPs: map[string]bool{"1.2.3.4": true}}
	if !s.isWildcardIP([]string{"5.6.7.8", "1.2.3.4"}) {
		t.Fatal("命中泛解析 IP 应返回 true")
	}
	if s.isWildcardIP([]string{"5.6.7.8"}) {
		t.Fatal("未命中泛解析 IP 应返回 false")
	}
	if (&DomainScanner{}).isWildcardIP([]string{"1.2.3.4"}) {
		t.Fatal("未检测过泛解析时应返回 false")
	}
}

func TestT8ClassifyCDNType(t *testing.T) {
	cases := map[string]string{
		"阿里云CDN":         "cloud",
		"AWS CloudFront": "cloud",
		"Cloudflare":     "commercial",
		"网宿CDN":          "commercial",
		"Unknown":        "unknown",
	}
	for provider, want := range cases {
		if got := classifyCDNType(provider); got != want {
			t.Fatalf("classifyCDNType(%q)=%q，期望 %q", provider, got, want)
		}
	}
	if len(GetCDNProviders()) == 0 {
		t.Fatal("CDN provider 列表不应为空")
	}
}
