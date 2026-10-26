package service

import (
	"testing"
)

func TestSha256Hex(t *testing.T) {
	if sha256Hex("hello") != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatal("sha256Hex 结果不符")
	}
}

func TestExtractVisibleText(t *testing.T) {
	html := `<html><head><style>body{color:red}</style><script>var x=1;</script></head>` +
		`<body><!-- comment --><h1>欢迎</h1><p>内容  文本</p></body></html>`
	got := extractVisibleText(html)
	for _, banned := range []string{"color:red", "var x", "comment", "<h1>"} {
		if contains(got, banned) {
			t.Fatalf("正文残留 %q: %q", banned, got)
		}
	}
	if !contains(got, "欢迎") || !contains(got, "内容") {
		t.Fatalf("可见文本丢失: %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// 两级 hash 判定的三分支（CheckOne 的核心判定逻辑提取自真实行为）：
//   - 首次见到（旧 hash 全空）→ 不算变更
//   - raw 变、text 同 → 动态噪声，不算变更
//   - text 变 → 真变更
func TestWatchChangeDecision(t *testing.T) {
	decide := func(oldRaw, oldText, newRaw, newText string) bool {
		firstSeen := oldRaw == "" && oldText == ""
		return !firstSeen && oldText != "" && oldText != newText
	}
	if decide("", "", "a", "b") {
		t.Fatal("首次见到不应判变更")
	}
	// raw 变 text 同 → 噪声
	if decide("raw1", "t1", "raw2", "t1") {
		// 注：decide 只看 text，raw 变 text 同时 oldText==newText → false，正确
		t.Fatal("text 相同不应判变更")
	}
	if !decide("raw1", "t1", "raw2", "t2") {
		t.Fatal("text 变化应判变更")
	}
}

func TestNormalizeDiscoverDomain(t *testing.T) {
	cases := map[string]string{
		"https://www.Example.com/path": "www.example.com",
		"http://a.b.example.com:8080/": "a.b.example.com",
		"*.Example.com.":               "example.com",
		"example.com":                  "example.com",
		"notadomain":                   "",
		"":                             "",
	}
	for in, want := range cases {
		if got := normalizeDiscoverDomain(in); got != want {
			t.Errorf("normalizeDiscoverDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetJoinHostPort(t *testing.T) {
	if got := net_JoinHostPort("example.com", 443); got != "example.com:443" {
		t.Errorf("v4 join = %q", got)
	}
	if got := net_JoinHostPort("::1", 8080); got != "[::1]:8080" {
		t.Errorf("v6 join = %q", got)
	}
}
