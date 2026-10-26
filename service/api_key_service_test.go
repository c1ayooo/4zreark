package service

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	raw, prefix, hash, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey: %v", err)
	}
	if !strings.HasPrefix(raw, APIKeyPrefix) {
		t.Fatalf("明文前缀不对: %s", raw)
	}
	if len(raw) != len(APIKeyPrefix)+64 {
		t.Fatalf("明文长度应为 %d，实际 %d", len(APIKeyPrefix)+64, len(raw))
	}
	if !strings.HasPrefix(raw, prefix) || len(prefix) != len(APIKeyPrefix)+8 {
		t.Fatalf("展示前缀不对: prefix=%q raw=%q", prefix, raw)
	}
	sum := sha256.Sum256([]byte(raw))
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatal("哈希与明文不匹配")
	}

	raw2, _, hash2, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey: %v", err)
	}
	if raw == raw2 || hash == hash2 {
		t.Fatal("两次生成不应重复")
	}
}

func TestNormalizeAPIKeyInputProjectScope(t *testing.T) {
	zero := int64(0)
	in, err := normalizeAPIKeyInput(APIKeyInput{Name: "  mcp  ", ProjectID: &zero})
	if err != nil {
		t.Fatalf("normalizeAPIKeyInput: %v", err)
	}
	if in.ProjectID != nil {
		t.Fatal("project_id=0 应归一成 nil（全部项目）")
	}
	if in.Name != "mcp" {
		t.Fatalf("名称未 trim: %q", in.Name)
	}

	neg := int64(-1)
	if _, err := normalizeAPIKeyInput(APIKeyInput{Name: "x", ProjectID: &neg}); err == nil {
		t.Fatal("负数项目 ID 应报错")
	}
	if _, err := normalizeAPIKeyInput(APIKeyInput{Name: "   "}); err == nil {
		t.Fatal("空名称应报错")
	}
}
