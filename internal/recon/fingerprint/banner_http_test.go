package fingerprint

import (
	"strings"
	"testing"
)

// HTTPBanner：状态行 + 头，超长截断。
func TestHTTPBanner(t *testing.T) {
	got := HTTPBanner("200 OK", "Server: nginx\r\nContent-Type: text/html\r\n")
	if !strings.HasPrefix(got, "200 OK\r\n") {
		t.Fatalf("banner 应以状态行开头，实际 %q", got)
	}
	if !strings.Contains(got, "Server: nginx") {
		t.Fatalf("banner 应包含响应头，实际 %q", got)
	}

	huge := strings.Repeat("A", maxBannerLen+1024)
	if n := len(HTTPBanner("200 OK", huge)); n > maxBannerLen {
		t.Fatalf("banner 应截断到 %d，实际 %d", maxBannerLen, n)
	}
}

// banner-only 规则在 HTTP 观测上要能命中：这是 1393 条规则从「永远不命中」
// 变成「可用」的关键，回归时必须守住。
func TestBannerOnlyRuleMatchesHTTPObservation(t *testing.T) {
	expr, err := ParseExpression(`banner="nginx"`)
	if err != nil {
		t.Fatalf("解析 banner 表达式失败: %v", err)
	}
	rules := []CompiledRule{{Name: "nginx", Category: "server", Expression: `banner="nginx"`, Expr: expr}}

	hit := Observation{
		Status: 200,
		Server: "nginx",
		Banner: HTTPBanner("200 OK", "Server: nginx\r\nContent-Type: text/html\r\n"),
	}
	if len(MatchObservation(rules, hit)) == 0 {
		t.Fatal("带 banner 的 HTTP 观测应命中 banner=\"nginx\"")
	}

	miss := Observation{
		Status: 200,
		Server: "nginx",
	}
	if got := MatchObservation(rules, miss); len(got) != 0 {
		t.Fatalf("没有 banner 字段时不应命中 banner-only 规则，实际命中 %d 条", len(got))
	}
}
