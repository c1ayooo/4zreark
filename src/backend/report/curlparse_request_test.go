package report

import (
	"strings"
	"testing"
)

func TestParseCurlRequest_PostFull(t *testing.T) {
	content := "验证请求：\ncurl -X POST 'http://t.com/api/login' \\\n  -H 'Content-Type: application/json' \\\n  -H 'Cookie: sid=abc123' \\\n  --data-raw '{\"user\":\"admin\\\"--\"}'\n{\"code\":0}"
	req, ok := ParseCurlRequest(content)
	if !ok {
		t.Fatal("应解析出 curl 请求")
	}
	if req.Method != "POST" || req.URL != "http://t.com/api/login" {
		t.Errorf("方法/URL 错误: %s %s", req.Method, req.URL)
	}
	if !hasHdr(req.Headers, "Content-Type", "application/json") {
		t.Errorf("缺 Content-Type 头: %v", req.Headers)
	}
	if !hasHdr(req.Headers, "Cookie", "sid=abc123") {
		t.Errorf("缺 Cookie 头: %v", req.Headers)
	}
	if !strings.Contains(req.Body, "admin\\\"--") {
		t.Errorf("请求体错误: %s", req.Body)
	}
}

func TestParseCurlRequest_DefaultsAndFlags(t *testing.T) {
	req, ok := ParseCurlRequest("curl -s -k -L 'https://t.com/user/1001' -b 'token=xyz' -A 'Mozilla/5.0'")
	if !ok {
		t.Fatal("应解析出 curl 请求")
	}
	if req.Method != "GET" {
		t.Errorf("默认方法应为 GET: %s", req.Method)
	}
	if !hasHdr(req.Headers, "Cookie", "token=xyz") {
		t.Errorf("-b 应合成 Cookie 头: %v", req.Headers)
	}
	if req.UserAgent != "Mozilla/5.0" {
		t.Errorf("缺 -A 指定的 UA: %q", req.UserAgent)
	}
}

func TestParseCurlRequest_NoCurlOrInvalid(t *testing.T) {
	if _, ok := ParseCurlRequest("nmap -sV target.com\n80/tcp open"); ok {
		t.Error("无 curl 不应解析成功")
	}
	if _, ok := ParseCurlRequest("curl -sS -k --insecure"); ok {
		t.Error("无 URL 不应解析成功")
	}
	if _, ok := ParseCurlRequest("=== REQUEST ===\nGET / HTTP/1.1\n"); ok {
		t.Error("已是报文格式无需解析（无 curl 词）")
	}
}

func TestContainsCurlCommand(t *testing.T) {
	cases := map[string]bool{
		"curl http://x.com":         true,
		"先 curl -k 再看响应":            true,
		"用 curlx 工具":                false, // 词内 curl 不算
		"文档里提到 curl 的用法":            true,  // 后接空格即算命令词（宽松）
		"curl -X POST 'http://t/' ": true,
	}
	for in, want := range cases {
		if got := ContainsCurlCommand(in); got != want {
			t.Errorf("ContainsCurlCommand(%q) = %v, 期望 %v", in, got, want)
		}
	}
}

func hasHdr(headers []string, key, val string) bool {
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), strings.ToLower(key)+":") && strings.Contains(h, val) {
			return true
		}
	}
	return false
}
