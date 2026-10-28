// Package secretbox 是长期凭据的统一信封加密层（安全审计 M13）。
//
// 密钥只来自环境变量 ZRE_SECRET_KEY（与 source_credentials 的既有机制同源）：
// 64 位十六进制 / base64 / 32 字节原始字符串。
//
// 存储格式："enc:v1:<base64(nonce)>:<base64(ciphertext)>"（AES-256-GCM）。
// DecryptText 对不带前缀的存量明文原样返回——双读兼容，迁移期间新旧格式共存；
// 迁移完成后库内不应再有不带前缀的凭据值。
//
// 写路径必须加密：未配置密钥时 EncryptText 报错，调用方拒绝保存（不降级明文）。
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Prefix 是加密值的版本前缀。
const Prefix = "enc:v1:"

const keyEnv = "ZRE_SECRET_KEY"

// HasKey 报告主密钥是否已配置。
func HasKey() bool {
	return strings.TrimSpace(os.Getenv(keyEnv)) != ""
}

func key() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(keyEnv))
	if raw == "" {
		return nil, errors.New("未配置 ZRE_SECRET_KEY，拒绝保存凭据")
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, errors.New("ZRE_SECRET_KEY 格式不正确（需要 32 字节 / 64 位 hex / base64）")
}

func gcm() (cipher.AEAD, error) {
	k, err := key()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptText 加密为带版本前缀的单串，直接可存 TEXT 列。
func EncryptText(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	a, err := gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := a.Seal(nil, nonce, []byte(plain), nil)
	return Prefix + base64.StdEncoding.EncodeToString(nonce) + ":" +
		base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptText 解密带前缀的密文；不带前缀的存量明文原样返回（双读兼容）。
func DecryptText(stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, Prefix) {
		return stored, nil
	}
	body := strings.TrimPrefix(stored, Prefix)
	parts := strings.SplitN(body, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("加密值格式无效")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("nonce 解码失败: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("密文解码失败: %w", err)
	}
	a, err := gcm()
	if err != nil {
		return "", err
	}
	plain, err := a.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("解密失败（密钥是否轮换过？）: %w", err)
	}
	return string(plain), nil
}
