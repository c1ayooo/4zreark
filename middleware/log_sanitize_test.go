package middleware

import "testing"

// 安全审计 M8：访问日志里的凭据类 query 参数值必须打码。
func TestSanitizeQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"token=abc.def.ghi", "token=[REDACTED]"},
		{"page=1&token=abc", "page=1&token=[REDACTED]"},
		{"Token=Abc", "Token=[REDACTED]"},
		{"access_token=xyz&limit=5", "access_token=[REDACTED]&limit=5"},
		{"page=2", "page=2"},
		{"", ""},
		{"keyword=token", "keyword=token"}, // 值里含 token 字样不属于凭据参数
	}
	for _, c := range cases {
		if got := SanitizeQuery(c.in); got != c.want {
			t.Fatalf("SanitizeQuery(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}
