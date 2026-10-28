package service

import (
	"strings"
	"testing"
)

// 安全审计 H4 验证：自动验证落库的原始报文必须先脱敏凭据模式，
// 漏洞详情（仅要求登录）不再可读到明文凭据。
func TestMaskRawTraffic(t *testing.T) {
	req := "POST /api/login HTTP/1.1\r\n" +
		"Host: target.example.com\r\n" +
		"Authorization: Bearer ghp_0123456789abcdef0123456789abcdef\r\n" +
		"Cookie: session=abc123def456; theme=dark\r\n" +
		"\r\n" +
		"username=admin&password=SuperSecret99&next=/"
	out := maskRawTraffic(req)

	if strings.Contains(out, "ghp_0123") {
		t.Fatalf("Authorization token 应被掩码: %s", out)
	}
	if strings.Contains(out, "abc123def456") {
		t.Fatalf("Cookie 值应被掩码: %s", out)
	}
	if strings.Contains(out, "SuperSecret99") {
		t.Fatalf("口令参数应被掩码: %s", out)
	}
	// 结构与非敏感信息保留
	if !strings.Contains(out, "POST /api/login HTTP/1.1") {
		t.Fatalf("请求行应保留")
	}
	if !strings.Contains(out, "theme=dark") {
		t.Fatalf("非敏感 Cookie 应保留")
	}
	if !strings.Contains(out, "username=admin") {
		t.Fatalf("非敏感参数应保留")
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("掩码标记应存在")
	}

	resp := "HTTP/1.1 200 OK\r\nSet-Cookie: session=xyz789; Path=/\r\nContent-Type: text/html\r\n\r\nok"
	outResp := maskRawTraffic(resp)
	if strings.Contains(outResp, "xyz789") {
		t.Fatalf("Set-Cookie 值应被掩码: %s", outResp)
	}
	if !strings.Contains(outResp, "Set-Cookie: session=[REDACTED]") {
		t.Fatalf("Set-Cookie 结构应保留: %s", outResp)
	}
}

// 幂等：对已脱敏报文再次应用不产生二次破坏。
func TestMaskRawTrafficIdempotent(t *testing.T) {
	raw := "Authorization: Bearer abc123\r\npassword=topsecret\r\n"
	once := maskRawTraffic(raw)
	twice := maskRawTraffic(once)
	if once != twice {
		t.Fatalf("脱敏应幂等:\n一次: %q\n两次: %q", once, twice)
	}
}

// 空报文直通。
func TestMaskRawTrafficEmpty(t *testing.T) {
	if got := maskRawTraffic(""); got != "" {
		t.Fatalf("空报文应返回空: %q", got)
	}
}
