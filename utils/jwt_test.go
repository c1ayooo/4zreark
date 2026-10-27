package utils

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/config"
)

// ParseToken 前置快拒（审计 M9）：未认证的超长/多段输入在进入解析器前被丢弃，
// 分配量不随分隔符数量增长；正常令牌不受影响。
func TestParseTokenRejectsMalformedInput(t *testing.T) {
	config.LoadConfigRaw([]byte("jwt:\n  secret: \"unit-test-secret\"\n  expire: 7200\n"))

	// 大量分隔符：快拒且耗时与段数无关
	polluted := strings.Repeat("a.", 100000) + "b"
	if _, err := ParseToken(polluted); err == nil {
		t.Fatalf("多段垃圾输入应被拒绝")
	}

	// 超长输入
	if _, err := ParseToken(strings.Repeat("x", 5000)); err == nil {
		t.Fatalf("超长输入应被拒绝")
	}

	// 空输入
	if _, err := ParseToken(""); err == nil {
		t.Fatalf("空输入应被拒绝")
	}

	// 正常签发→解析闭环仍工作
	token, err := GenerateTokenClaims("u1", "tester", "admin", 1, false)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	claims, err := ParseToken(token)
	if err != nil {
		t.Fatalf("正常令牌不应被前置校验误伤: %v", err)
	}
	if claims.UserID != "u1" || claims.Username != "tester" {
		t.Fatalf("claims 解析不符: %+v", claims)
	}
}
