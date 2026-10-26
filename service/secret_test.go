package service

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestEncryptDecryptSecret(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	t.Setenv("ZRE_SECRET_KEY", hex.EncodeToString(key))

	ct, nonce, err := EncryptSecret("super-secret-key")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if string(ct) == "super-secret-key" {
		t.Fatal("密文不应包含明文")
	}
	plain, err := DecryptSecret(ct, nonce)
	if err != nil || plain != "super-secret-key" {
		t.Fatalf("解密不符: %q err=%v", plain, err)
	}
}

func TestSecretKeyFormats(t *testing.T) {
	raw := bytes.Repeat([]byte{0x01}, 32)
	for _, key := range []string{
		string(raw),
		hex.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
	} {
		t.Setenv("ZRE_SECRET_KEY", key)
		if _, _, err := EncryptSecret("x"); err != nil {
			t.Fatalf("密钥格式 %q 应可用: %v", key, err)
		}
	}
}

func TestSecretRequiresKey(t *testing.T) {
	t.Setenv("ZRE_SECRET_KEY", "")
	if _, _, err := EncryptSecret("x"); err == nil {
		t.Fatal("未配置 ZRE_SECRET_KEY 时应拒绝加密")
	}
	t.Setenv("ZRE_SECRET_KEY", "too-short")
	if _, _, err := EncryptSecret("x"); err == nil {
		t.Fatal("非法密钥长度应被拒绝")
	}
}
