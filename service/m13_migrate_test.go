package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/internal/secretbox"
)

// 安全审计 M13 验证：通知配置 JSON 的密钥字段迁移——明文→密文、已加密跳过（幂等）。
func TestEncryptNotifyJSON(t *testing.T) {
	t.Setenv("ZRE_SECRET_KEY", "0123456789abcdef0123456789abcdef")

	// 明文字段 → 全部加密
	plain := []byte(`{"smtp_host":"smtp.corp.com","smtp_password":"p@ss1234","dingtalk_secret":"sec123"}`)
	out, changed, err := encryptNotifyJSON(plain)
	if err != nil || !changed {
		t.Fatalf("明文应被加密: changed=%v err=%v", changed, err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	pwd, _ := m["smtp_password"].(string)
	if !strings.HasPrefix(pwd, secretbox.Prefix) {
		t.Fatalf("smtp_password 应为密文: %q", pwd)
	}
	if secret, _ := m["dingtalk_secret"].(string); !strings.HasPrefix(secret, secretbox.Prefix) {
		t.Fatalf("dingtalk_secret 应为密文: %q", secret)
	}
	if m["smtp_host"] != "smtp.corp.com" {
		t.Fatalf("非密钥字段不应改动")
	}
	// 解密回读一致
	if got, derr := secretbox.DecryptText(pwd); derr != nil || got != "p@ss1234" {
		t.Fatalf("密文应可解密回读: %q err=%v", got, derr)
	}

	// 已全部加密 → 幂等无改动
	out2, changed2, err := encryptNotifyJSON(out)
	if err != nil || changed2 {
		t.Fatalf("已加密配置应跳过: changed=%v err=%v", changed2, err)
	}
	if string(out2) != string(out) {
		t.Fatalf("幂等运行不应改动内容")
	}
}
