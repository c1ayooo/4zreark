package service

import (
	"strings"
	"testing"
)

// 安全审计 M6 验证：凭据测试 endpoint 必须落在 GitHub 主机白名单内，
// 后缀仿冒域名与非 https 一律拒绝；企业版主机经 env 显式放行。
func TestCheckSourceEndpointHost(t *testing.T) {
	t.Setenv("ZRE_GITHUB_EXTRA_HOSTS", "")
	good := []string{
		"https://api.github.com/rate_limit",
		"https://github.com/foo/bar",
		"https://Gist.GitHub.COM/x",
	}
	for _, u := range good {
		if err := CheckSourceEndpointHost(u); err != nil {
			t.Fatalf("白名单内应放行 %s: %v", u, err)
		}
	}
	bad := []string{
		"http://api.github.com/x",            // 非 https
		"https://evil-github.com/x",          // 后缀仿冒
		"https://github.com.evil.io/x",       // 前缀仿冒
		"https://api.github.com.evil.io/x",   // 深层仿冒
		"ftp://github.com/x",                 // 协议不对
		"https://user@github.com@evil.io/x",  // userinfo 混淆
		"not a url",
	}
	for _, u := range bad {
		if err := CheckSourceEndpointHost(u); err == nil {
			t.Fatalf("应拒绝 %s", u)
		} else if !strings.Contains(err.Error(), "白名单") && !strings.Contains(err.Error(), "https") {
			t.Fatalf("拒绝原因应明确: %v", err)
		}
	}
	// 企业版主机显式放行
	t.Setenv("ZRE_GITHUB_EXTRA_HOSTS", "ghe.corp.example.com,  GHE2.corp.example.com ")
	if err := CheckSourceEndpointHost("https://ghe.corp.example.com/api/v3/rate_limit"); err != nil {
		t.Fatalf("GHE 白名单应放行: %v", err)
	}
	if err := CheckSourceEndpointHost("https://ghe2.corp.example.com/"); err != nil {
		t.Fatalf("GHE 白名单大小写应不敏感: %v", err)
	}
	if err := CheckSourceEndpointHost("https://corp.example.com/"); err == nil {
		t.Fatalf("未列入白名单的企业域仍应拒绝")
	}
}
