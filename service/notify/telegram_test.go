package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sendMessage 请求形态正确、成功路径不报错。
func TestTelegramNotifierSend(t *testing.T) {
	var gotPath string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := NewTelegramNotifier("12345:ABC-token", "-100998877")
	n.client = srv.Client()
	n.apiBase = srv.URL

	msg := &NotifyMessage{
		Level:   NotifyLevelWarning,
		Title:   "发现高危漏洞",
		Source:  "vulnscan",
		Content: "target=https://example.com",
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.HasPrefix(gotPath, "/bot12345:ABC-token/sendMessage") {
		t.Fatalf("请求路径不对: %s", gotPath)
	}
	if gotBody["chat_id"] != "-100998877" {
		t.Fatalf("chat_id 丢失: %v", gotBody)
	}
	if !strings.Contains(gotBody["text"], "发现高危漏洞") {
		t.Fatalf("标题丢失: %v", gotBody)
	}
}

// 非 200 响应报错且带响应体摘要，便于配置排错。
func TestTelegramNotifierError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	defer srv.Close()

	n := NewTelegramNotifier("bad-token", "1")
	n.client = srv.Client()
	n.apiBase = srv.URL

	err := n.Send(context.Background(), &NotifyMessage{Title: "t"})
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("应报错并带 API 描述，实际 %v", err)
	}
}

// 缺 token / chat_id 直接拒绝，不发请求。
func TestTelegramNotifierMissingConfig(t *testing.T) {
	n := NewTelegramNotifier("", "1")
	if err := n.Send(context.Background(), &NotifyMessage{Title: "t"}); err == nil {
		t.Fatal("缺 token 应报错")
	}
}

// 工厂：telegram 配置创建出 TelegramNotifier；缺 chat_id 不创建。
func TestCreateNotifierTelegram(t *testing.T) {
	m := NewNotifyManager()
	defer m.Stop()

	n := m.createNotifier(NotifyConfig{
		Type:             NotifyTypeTelegram,
		TelegramBotToken: "tok",
		TelegramChatID:   "42",
	})
	if _, ok := n.(*TelegramNotifier); !ok {
		t.Fatalf("应创建 TelegramNotifier，实际 %T", n)
	}
	if m.createNotifier(NotifyConfig{Type: NotifyTypeTelegram, TelegramBotToken: "tok"}) != nil {
		t.Fatal("缺 chat_id 不应创建通知器")
	}
}
