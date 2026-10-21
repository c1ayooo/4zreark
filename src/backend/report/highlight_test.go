package report

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/internal/httpprobe"
)

func TestHighlightResponse_SensitiveFields(t *testing.T) {
	resp := "HTTP/1.1 200 OK\n{\"access_token\":\"abc123\",\"nickname\":\"张三\"}"
	out := string(HighlightResponse(resp, "", "", ""))
	if !strings.Contains(out, `<mark class="hl">`) {
		t.Fatal("应包含高亮标记")
	}
	// access_token 键值对整体命中（引号经 HTML 转义为 &#34;）；nickname 不命中
	if !strings.Contains(out, `<mark class="hl">&#34;access_token&#34;:&#34;abc123</mark>`) {
		t.Errorf("敏感键值未命中: %s", out)
	}
	if strings.Contains(out, `nickname&#34;:&#34;张三</mark>`) {
		t.Error("非敏感字段不应命中")
	}
	// 整体转义完整性：文本未变形
	plain := stripMarks(out)
	if !strings.Contains(plain, `&#34;nickname&#34;:&#34;张三&#34;`) {
		t.Errorf("非高亮文本应原样转义保留: %s", plain)
	}
}

func TestHighlightResponse_JWTAndIDCard(t *testing.T) {
	// 两处独立命中（JWT 与身份证不与其它模式重叠）
	resp := "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345678\nid=11010119900307867X"
	out := string(HighlightResponse(resp, "", "", ""))
	if strings.Count(out, `<mark class="hl">`) != 2 {
		t.Errorf("应命中 2 处（JWT/身份证），实际:\n%s", out)
	}
	if !strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") || !strings.Contains(out, "11010119900307867X") {
		t.Errorf("命中内容缺失: %s", out)
	}
}

func TestHighlightResponse_RequestEcho(t *testing.T) {
	req := httpprobe.RequestMarker + "\nGET /api/user?id=10017322 HTTP/1.1\n\n"
	resp := "HTTP/1.1 200 OK\n{\"data\":{\"uid\":10017322,\"name\":\"李四\"}}"
	out := string(HighlightResponse(resp, req, "越权", ""))
	if !strings.Contains(out, `<mark class="hl">10017322</mark>`) {
		t.Errorf("请求回显值应高亮: %s", out)
	}
}

func TestHighlightResponse_VulnTypePattern(t *testing.T) {
	resp := "HTTP/1.1 500\nyou have an error in your SQL syntax near '1'"
	out := string(HighlightResponse(resp, "", "SQL注入", ""))
	if !strings.Contains(out, `<mark class="hl">`) || !strings.Contains(strings.ToLower(out), "sql syntax") {
		t.Errorf("SQL 注入特征未高亮: %s", out)
	}
	// 同样内容在非 SQL 类型下不命中类型特征
	out2 := string(HighlightResponse(resp, "", "信息泄露", ""))
	if strings.Contains(strings.ToLower(out2), `<mark class="hl">you have`) {
		t.Error("类型不匹配不应命中特征")
	}
}

func TestHighlightResponse_XSSEscaped(t *testing.T) {
	// 响应含脚本标签：展示为转义文本且高亮包裹的是转义后的 <script>…
	resp := "HTTP/1.1 200 OK\n<div><script>alert(1)</script></div>"
	out := string(HighlightResponse(resp, "", "XSS", ""))
	if strings.Contains(out, "<script>") {
		t.Errorf("高亮输出不得包含未转义脚本标签: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("脚本标签应转义呈现")
	}
	if !strings.Contains(out, `<mark class="hl">`) {
		t.Error("XSS 特征应高亮")
	}
}

func stripMarks(s string) string {
	return strings.NewReplacer(`<mark class="hl">`, "", "</mark>", "").Replace(s)
}

func TestShapePacket_HighlightIntegration(t *testing.T) {
	resp := strings.Repeat("A", 4*1024) + `{"password":"P@ss1234"}` + strings.Repeat("B", 4*1024)
	content := httpprobe.RequestMarker + "\nGET / HTTP/1.1\n\n" +
		httpprobe.ResponseMarker + "\nHTTP/1.1 200 OK\n\n" + resp
	item, ok := NewPacketItem(content, RespModeSmart, "", "")
	if !ok {
		t.Fatal("应识别报文")
	}
	if item.RespOmitted <= 0 {
		t.Fatal("smart 应节选")
	}
	if strings.Contains(string(item.RespHTML), "P@ss1234") {
		// 密码字段位于节选区之后 → 主卡不含；全量展开区必须高亮命中
		t.Error("节选区不应包含节选之后的密码字段")
	}
	if !strings.Contains(string(item.RespFullHTML), `<mark class="hl">&#34;password&#34;:&#34;P@ss1234</mark>`) {
		t.Error("展开区应高亮密码字段")
	}
}
