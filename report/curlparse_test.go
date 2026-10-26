package report

import (
	"strings"
	"testing"
)

func TestCurlToTranscript_PostWithHeaders(t *testing.T) {
	content := "curl -X POST 'http://t.com/api/login' -H 'Content-Type: application/x-www-form-urlencoded' --data-raw \"username=admin'--&password=x\"\n{\"code\":0,\"token\":\"...\"}"
	out, ok := CurlToTranscript(content)
	if !ok {
		t.Fatal("应识别为 curl")
	}
	if !strings.Contains(out, "POST /api/login HTTP/1.1") {
		t.Errorf("请求行错误: %s", firstLine(out))
	}
	if !strings.Contains(out, "Host: t.com") {
		t.Error("缺 Host 头")
	}
	if !strings.Contains(out, "Content-Type: application/x-www-form-urlencoded") {
		t.Error("缺 Content-Type 头")
	}
	if !strings.Contains(out, "username=admin'--&password=x") {
		t.Error("缺请求体")
	}
	if !strings.Contains(out, "=== RESPONSE ===") || !strings.Contains(out, "{\"code\":0") {
		t.Error("响应区未呈现 curl 输出")
	}
}

func TestCurlToTranscript_MultilineCookieGet(t *testing.T) {
	content := "curl 'http://t.com/user/1001' \\\n  -H 'Cookie: sid=abc123' \\\n  -b 'token=xyz' \\\n  -A 'Mozilla/5.0'\n200 OK user profile of other user"
	out, ok := CurlToTranscript(content)
	if !ok {
		t.Fatal("多行 curl 应识别")
	}
	if !strings.Contains(out, "GET /user/1001 HTTP/1.1") {
		t.Errorf("GET 请求行错误: %s", firstLine(out))
	}
	if !strings.Contains(out, "Cookie: sid=abc123") || !strings.Contains(out, "Cookie: token=xyz") {
		t.Error("Cookie 头缺失")
	}
	if !strings.Contains(out, "User-Agent: Mozilla/5.0") {
		t.Error("UA 头缺失")
	}
}

func TestCurlToTranscript_PlainURL(t *testing.T) {
	out, ok := CurlToTranscript("curl http://t.com:8080/health\n{\"status\":\"up\"}")
	if !ok || !strings.Contains(out, "GET /health HTTP/1.1") || !strings.Contains(out, "Host: t.com:8080") {
		t.Fatalf("裸 URL 解析失败: %s", out)
	}
}

func TestCurlToTranscript_NoCurl(t *testing.T) {
	content := "nmap -sV target.com\n80/tcp open http"
	out, ok := CurlToTranscript(content)
	if ok || out != content {
		t.Error("非 curl 内容应原样返回 false")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}
