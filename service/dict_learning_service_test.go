package service

import (
	"context"
	"testing"
)

// ExtractSubdomainLabel：相对根域的首段标签，爆破词位置；跨域/根域自身返回空。
func TestExtractSubdomainLabel(t *testing.T) {
	cases := []struct {
		host, root, want string
	}{
		{"api.example.com", "example.com", "api"},
		{"API.Example.COM", "example.com", "api"},
		{"a-b.example.com", "example.com", "a-b"},
		{"api.test.example.com", "example.com", "api"}, // 多级前缀取最左段
		{"api.test.example.com.", "example.com", "api"},
		{"example.com", "example.com", ""},  // 根域自身
		{"other.com", "example.com", ""},    // 不以根域结尾
		{"", "example.com", ""},
		{"api.example.com", "", ""},
		{"-bad.example.com", "example.com", ""}, // 非法标签
		{"a_b.example.com", "example.com", ""},  // 下划线不是合法 DNS 标签
	}
	for _, c := range cases {
		if got := ExtractSubdomainLabel(c.host, c.root); got != c.want {
			t.Fatalf("ExtractSubdomainLabel(%q,%q) = %q, want %q", c.host, c.root, got, c.want)
		}
	}
}

// ExtractLearnedPath：去文件名/ID 段，限 3 段限长，脏字符拒绝。
func TestExtractLearnedPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://a.com/console/login", "/console/login"},
		{"https://a.com/api/v1/user/123", "/api/v1/user"},
		{"https://a.com/admin/index.php", "/admin"},
		{"https://a.com/static/app.js", "/static"},
		{"https://a.com/u/550e8400-e29b-41d4-a716-446655440000", "/u"},
		{"https://a.com/file/0123456789abcdef0123456789abcdef", "/file"},
		{"https://a.com/", ""},
		{"https://a.com", ""},
		{"https://a.com/api?x=1", "/api"},
		{"https://a.com/actuator/env", "/actuator/env"},
		{"https://a.com/a b/c", ""}, // 空格等脏字符
		{"https://a.com/" + repeat("s", 50) + "/" + repeat("t", 50) + "/" + repeat("u", 50), ""}, // 超长
	}
	for _, c := range cases {
		if got := ExtractLearnedPath(c.in); got != c.want {
			t.Fatalf("ExtractLearnedPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func repeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}

// 配置默认值与校验：repo 未初始化时读默认、写报错。
func TestDictLearningConfigDefaults(t *testing.T) {
	cfg, err := LoadDictLearningConfig(context.Background())
	if err != nil {
		t.Fatalf("读配置不应报错: %v", err)
	}
	if !cfg.Enabled || cfg.SubdomainMinHits != 3 || cfg.PathMinHits != 3 {
		t.Fatalf("默认配置不符: %+v", cfg)
	}
	bad := DefaultDictLearningConfig()
	bad.SubdomainMinHits = 0
	if err := SaveDictLearningConfig(context.Background(), bad); err == nil {
		t.Fatal("阈值 0 应被拒绝")
	}
}
