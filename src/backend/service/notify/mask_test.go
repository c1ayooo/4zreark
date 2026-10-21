package notify

import (
	"context"
	"strings"
	"testing"
)

type fakeNotifier struct {
	msgs []*NotifyMessage
}

func (f *fakeNotifier) Type() NotifyType { return NotifyTypeWebhook }
func (f *fakeNotifier) Send(_ context.Context, msg *NotifyMessage) error {
	f.msgs = append(f.msgs, msg)
	return nil
}

func TestMaskSensitive(t *testing.T) {
	in := `password=abc123 token: "tok_xxx" Authorization: Bearer eyJhbGciOi
AKIAABCDEFGHIJKLMNOP
phone 13812345678 id 11010519491231002X
-----BEGIN RSA PRIVATE KEY-----
secret
-----END RSA PRIVATE KEY-----`
	out := MaskSensitive(in)
	for _, leaked := range []string{"abc123", "tok_xxx", "eyJhbGciOi", "AKIAABCDEFGHIJKLMNOP", "13812345678", "11010519491231002X", "BEGIN RSA PRIVATE KEY"} {
		if strings.Contains(out, leaked) {
			t.Errorf("未脱敏 %q: %s", leaked, out)
		}
	}
	for _, want := range []string{"password=***", "token=***", "Authorization=***", "AKIA****************", "138****5678", "110105********002X", "[PRIVATE KEY REDACTED]"} {
		if !strings.Contains(out, want) {
			t.Errorf("缺少脱敏结果 %q: %s", want, out)
		}
	}
}

func TestMaskMessage(t *testing.T) {
	msg := &NotifyMessage{
		Title:   "token=abc",
		Content: "联系 13812345678",
		Extra:   map[string]interface{}{"secret": "password=xyz", "items": []string{"Bearer abc"}},
	}
	MaskMessage(msg)
	if strings.Contains(msg.Title, "abc") || strings.Contains(msg.Content, "13812345678") {
		t.Fatalf("标题/正文未脱敏: %+v", msg)
	}
	if strings.Contains(msg.Extra["secret"].(string), "xyz") {
		t.Fatalf("extra 未脱敏: %+v", msg.Extra)
	}
	if got := msg.Extra["items"].([]string)[0]; strings.Contains(got, "abc") {
		t.Fatalf("extra 数组未脱敏: %q", got)
	}
}

func TestNotifyLevelFilter(t *testing.T) {
	t.Setenv("ZRE_NOTIFY_MIN_LEVEL", "warning")
	if NotifyLevelAllowed(NotifyLevelInfo) {
		t.Fatal("info 应被过滤")
	}
	if !NotifyLevelAllowed(NotifyLevelWarning) || !NotifyLevelAllowed(NotifyLevelCritical) {
		t.Fatal("warning/critical 应放行")
	}
}

func TestManagerMasksAndFilters(t *testing.T) {
	t.Setenv("ZRE_NOTIFY_MIN_LEVEL", "warning")
	m := NewNotifyManager()
	fake := &fakeNotifier{}
	m.notifiers = []Notifier{fake}

	_ = m.Send(context.Background(), &NotifyMessage{Level: NotifyLevelInfo, Title: "info", Content: "password=abc"})
	if len(fake.msgs) != 0 {
		t.Fatalf("info 级不应发送，实际 %d", len(fake.msgs))
	}
	_ = m.Send(context.Background(), &NotifyMessage{Level: NotifyLevelCritical, Title: "critical", Content: "password=abc"})
	if len(fake.msgs) != 1 {
		t.Fatalf("critical 应发送，实际 %d", len(fake.msgs))
	}
	if strings.Contains(fake.msgs[0].Content, "abc") {
		t.Fatalf("发送内容未脱敏: %s", fake.msgs[0].Content)
	}
}

func TestValidateWebhookURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool // valid
	}{
		{"http://127.0.0.1:8080/hook", false},
		{"http://10.0.0.1/hook", false},
		{"http://169.254.169.254/latest/meta-data", false},
		{"ftp://example.com/hook", false},
		{"https://8.8.8.8/hook", true},
	}
	for _, tc := range cases {
		err := validateWebhookURL(tc.url)
		if (err == nil) != tc.want {
			t.Errorf("validateWebhookURL(%s) err=%v want valid=%v", tc.url, err, tc.want)
		}
	}
	t.Setenv("ZRE_NOTIFY_ALLOW_PRIVATE", "1")
	if err := validateWebhookURL("http://127.0.0.1:8080/hook"); err != nil {
		t.Fatalf("允许内网时应通过: %v", err)
	}
}
