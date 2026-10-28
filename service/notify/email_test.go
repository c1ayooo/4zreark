package notify

import (
	"context"
	"strings"
	"testing"
)

// 安全审计 §5（邮件 HTML）：通知内容来源广泛，HTML 邮件必须转义；
// Subject 是邮件头，标题里的 CRLF 必须剥离（防头部注入）。
func TestBuildHTMLBodyEscapes(t *testing.T) {
	n := &EmailNotifier{}
	msg := &NotifyMessage{
		Level:   NotifyLevelCritical,
		Title:   `<script>alert("x")</script>`,
		Source:  `task"><img src=x onerror=alert(1)>`,
		Content: "第一行\n<script>alert(1)</script>\n第三行",
	}
	body := n.buildHTMLBody(msg)

	if strings.Contains(body, "<script>") {
		t.Fatalf("HTML 邮件不应包含未转义的 script 标签")
	}
	if strings.Contains(body, "<img") {
		t.Fatalf("img 标签不应以可执行形态存在（应为 &lt;img 文本）")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("应出现转义后的 script 文本")
	}
	// 换行仍在转义后转 <br>，三行结构保留
	if strings.Count(body, "<br>") != 2 {
		t.Fatalf("Content 换行应转成 <br>，实际 %d 处", strings.Count(body, "<br>"))
	}
}

func TestStripMailCRLF(t *testing.T) {
	injected := "正常标题\r\nBcc: victim@example.com\r\n"
	got := stripMailCRLF(injected)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("Subject 不得携带 CRLF: %q", got)
	}
	if !strings.Contains(got, "Bcc: victim@example.com") {
		t.Fatalf("换行应替换为空格保留可读性")
	}
}

// 编译期确认 EmailNotifier 实现通知器接口。
var _ Notifier = (*EmailNotifier)(nil)

var _ = context.Background
