package notify

import "testing"

// Telegram bot token 是脱敏回显字段：前端改渠道级别/触发测试时会把回显的
// 星号串原样传回，mergeMaskedSecrets 必须保住旧值（漏了会把渠道打挂）。
func TestMergeMaskedSecretsKeepsTelegramToken(t *testing.T) {
	existing := NotifyConfig{
		Name:             "tg",
		Type:             "telegram",
		TelegramBotToken: "123456:REAL-TOKEN",
		TelegramChatID:   "@channel",
	}
	in := NotifyConfig{
		Name:             "tg",
		Type:             "telegram",
		TelegramBotToken: "abcd****wxyz",
		TelegramChatID:   "@channel",
		MinLevel:         "warn",
	}
	got := mergeMaskedSecrets(in, existing)
	if got.TelegramBotToken != existing.TelegramBotToken {
		t.Fatalf("脱敏 token 应还原为旧值，实际 %q", got.TelegramBotToken)
	}
	if got.MinLevel != "warn" {
		t.Fatalf("其他字段应正常更新，MinLevel=%q", got.MinLevel)
	}
	// 新渠道或明文重填：原值直通
	in.TelegramBotToken = "123456:NEW-TOKEN"
	if got := mergeMaskedSecrets(in, existing); got.TelegramBotToken != "123456:NEW-TOKEN" {
		t.Fatalf("明文 token 应直通保存，实际 %q", got.TelegramBotToken)
	}
}
