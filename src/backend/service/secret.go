package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// G4：数据源凭据加密。密钥只从环境变量 ZRE_SECRET_KEY 读：
//   - 64 位十六进制，或
//   - base64，或
//   - 32 字节原始字符串
//
// 未配置密钥时明确拒绝保存凭据，不降级为明文。

func secretKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("ZRE_SECRET_KEY"))
	if raw == "" {
		return nil, errors.New("未配置 ZRE_SECRET_KEY，拒绝保存数据源凭据")
	}
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, errors.New("ZRE_SECRET_KEY 格式不正确（需要 32 字节 / 64 位 hex / base64）")
}

// EncryptSecret 返回 AES-256-GCM 密文与 nonce。
func EncryptSecret(plain string) (ciphertext, nonce []byte, err error) {
	key, err := secretKey()
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, []byte(plain), nil), nonce, nil
}

func DecryptSecret(ciphertext, nonce []byte) (string, error) {
	key, err := secretKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
