package secretbox

import (
	"os"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Setenv(keyEnv, "0123456789abcdef0123456789abcdef")

	stored, err := EncryptText("ghp_supersecret123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, Prefix) {
		t.Fatalf("密文应带版本前缀: %s", stored)
	}
	got, err := DecryptText(stored)
	if err != nil || got != "ghp_supersecret123" {
		t.Fatalf("往返不一致: %q err=%v", got, err)
	}

	// 空值直通
	if s, _ := EncryptText(""); s != "" {
		t.Fatalf("空值应返回空串")
	}
	if s, _ := DecryptText(""); s != "" {
		t.Fatalf("空值应返回空串")
	}
}

// 双读兼容：存量明文原样返回，迁移期间新旧格式共存。
func TestDecryptPlaintextPassthrough(t *testing.T) {
	t.Setenv(keyEnv, "0123456789abcdef0123456789abcdef")
	got, err := DecryptText("legacy-plain-cookie")
	if err != nil || got != "legacy-plain-cookie" {
		t.Fatalf("存量明文应原样返回: %q err=%v", got, err)
	}
}

// 未配置密钥：写路径拒绝（不降级明文），读路径明文仍可用。
func TestMissingKey(t *testing.T) {
	t.Setenv(keyEnv, "")
	os.Unsetenv(keyEnv)
	if HasKey() {
		t.Fatalf("未配置密钥时 HasKey 应为 false")
	}
	if _, err := EncryptText("x"); err == nil {
		t.Fatalf("未配置密钥时加密应报错")
	}
	if got, err := DecryptText("legacy-plain"); err != nil || got != "legacy-plain" {
		t.Fatalf("未配置密钥时存量明文读取应可用: %q err=%v", got, err)
	}
	// 密文在无密钥时读不出——报错而不是返回密文
	if _, err := DecryptText(Prefix + "AAAA:BBBB"); err == nil {
		t.Fatalf("无密钥解密应报错")
	}
}

// 密钥轮换后旧密文明确报错，不静默返回垃圾。
func TestWrongKeyFails(t *testing.T) {
	t.Setenv(keyEnv, "0123456789abcdef0123456789abcdef")
	stored, err := EncryptText("data")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(keyEnv, "fedcba9876543210fedcba9876543210")
	if _, err := DecryptText(stored); err == nil {
		t.Fatalf("换钥后解密应失败")
	}
}
