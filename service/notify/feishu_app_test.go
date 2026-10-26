package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFeishuAppNotifierTokenAndSend(t *testing.T) {
	var tokenCalls, messageCalls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			tokenCalls++
			var in struct {
				AppID     string `json:"app_id"`
				AppSecret string `json:"app_secret"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.AppID != "cli_test" || in.AppSecret != "secret_test" {
				t.Errorf("token 请求凭据错误: %+v", in)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 0, "msg": "ok", "tenant_access_token": "t-test", "expire": 7200,
			})
		case "/open-apis/im/v1/messages":
			messageCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer t-test" {
				t.Errorf("Authorization = %q", got)
			}
			if got := r.URL.Query().Get("receive_id_type"); got != "open_id" {
				t.Errorf("receive_id_type = %q", got)
			}
			var in struct {
				ReceiveID string `json:"receive_id"`
				MsgType   string `json:"msg_type"`
				Content   string `json:"content"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Errorf("解析发送请求失败: %v", err)
			}
			if in.ReceiveID != "ou_test" || in.MsgType != "interactive" {
				t.Errorf("发送请求错误: %+v", in)
			}
			var card map[string]interface{}
			if err := json.Unmarshal([]byte(in.Content), &card); err != nil {
				t.Errorf("content 不是卡片 JSON: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "msg": "success"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("ZRE_FEISHU_BASE_URL", srv.URL)

	n := NewFeishuAppNotifier("cli_test", "secret_test", "open_id", "ou_test")
	msg := &NotifyMessage{
		Level:     NotifyLevelWarning,
		Title:     "标题",
		Content:   "内容",
		Source:    "test",
		Timestamp: time.Now(),
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatalf("第一次发送失败: %v", err)
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatalf("第二次发送失败: %v", err)
	}
	if tokenCalls != 1 {
		t.Fatalf("token 应被缓存，实际请求 %d 次", tokenCalls)
	}
	if messageCalls != 2 {
		t.Fatalf("消息应发送 2 次，实际 %d 次", messageCalls)
	}
}

func TestFeishuAppNotifierRequiresReceiver(t *testing.T) {
	n := NewFeishuAppNotifier("cli_test", "secret_test", "chat_id", "")
	err := n.Send(context.Background(), &NotifyMessage{
		Level: NotifyLevelInfo, Title: "t", Timestamp: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "接收者") {
		t.Fatalf("缺少接收者时应报错，实际: %v", err)
	}
}

// TestFeishuAppNotifierLive 只有显式设置 ZRE_FEISHU_LIVE=1 时才发真实消息。
func TestFeishuAppNotifierLive(t *testing.T) {
	if os.Getenv("ZRE_FEISHU_LIVE") != "1" {
		t.Skip("设置 ZRE_FEISHU_LIVE=1 才执行真实飞书发送")
	}
	appID := os.Getenv("ZRE_FEISHU_APP_ID")
	appSecret := os.Getenv("ZRE_FEISHU_APP_SECRET")
	receiveIDType := os.Getenv("ZRE_FEISHU_RECEIVE_ID_TYPE")
	receiveID := os.Getenv("ZRE_FEISHU_RECEIVE_ID")
	if receiveIDType == "" {
		receiveIDType = "open_id"
	}
	if appID == "" || appSecret == "" || receiveID == "" {
		t.Fatal("缺少 ZRE_FEISHU_APP_ID / APP_SECRET / RECEIVE_ID")
	}

	n := NewFeishuAppNotifier(appID, appSecret, receiveIDType, receiveID)
	if err := n.Send(context.Background(), &NotifyMessage{
		Level:     NotifyLevelInfo,
		Title:     "4zreark 通知通道测试",
		Content:   "这条消息由 4zreark 的飞书企业应用 notifier 发送。",
		Source:    "notify_test",
		Timestamp: time.Now(),
	}); err != nil {
		t.Fatalf("真实发送失败: %v", err)
	}
}
