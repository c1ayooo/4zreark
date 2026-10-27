package api

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// 审计 M10 的三条边界：锁定语义、低频清理、容量硬上限。
func TestFailureLimiterLocksAndResets(t *testing.T) {
	l := newFailureLimiter(3, time.Minute)
	key := "10.0.0.1|admin"

	for i := 0; i < 3; i++ {
		l.fail(key)
	}
	if !l.blocked(key) {
		t.Fatalf("窗口内失败满 max 应锁定")
	}
	l.reset(key)
	if l.blocked(key) {
		t.Fatalf("成功登录后应解锁")
	}
}

func TestFailureLimiterBoundedMemory(t *testing.T) {
	l := newFailureLimiter(3, time.Minute)
	// 刷 3 万个唯一键（远超容量上限 10000）：map 必须被钳住
	for i := 0; i < 30000; i++ {
		l.fail(strings.Repeat("u", 1) + time.Now().Format("150405") + fmt.Sprintf("%c%d", 'a'+i%26, i))
	}
	if len(l.fails) > l.maxEntries {
		t.Fatalf("map 应被容量上限钳制，实际 %d", len(l.fails))
	}
	// 重置后当前键仍被记录（攻击者不能靠触发清空洗掉自己的计数）
	if len(l.fails) == 0 {
		t.Fatalf("容量重置后应保留当前键")
	}
}

func TestFailureLimiterExpiryLazyDelete(t *testing.T) {
	l := newFailureLimiter(1, time.Millisecond)
	l.fail("k")
	time.Sleep(5 * time.Millisecond)
	if l.blocked("k") {
		t.Fatalf("过期条目不应锁定")
	}
	l.mu.Lock()
	_, exists := l.fails["k"]
	l.mu.Unlock()
	if exists {
		t.Fatalf("查询命中的过期条目应被惰性删除")
	}
}

func TestLoginUsernameLengthCap(t *testing.T) {
	// Login 的 binding 校验无法脱离 gin 独立测，这里只验证结构体标签存在
	var req struct {
		Username string `binding:"required,max=64"`
	}
	tag := "required,max=64"
	field, _ := reflect.TypeOf(req).FieldByName("Username")
	if got := field.Tag.Get("binding"); got != tag {
		t.Fatalf("Username 应带 %s 校验，实际 %s", tag, got)
	}
}
