package test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/middleware"

	"github.com/gin-gonic/gin"
)

// Idempotency-Key：同 key 只执行一次，重放直接返回缓存；4xx 不缓存。
func TestIdempotencyMiddleware(t *testing.T) {
	r := openTestRepo(t)
	gin.SetMode(gin.TestMode)
	key := fmt.Sprintf("idem-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(t.Context(), `delete from idempotency_keys where path in ('/x','/bad') and user_id=''`)
	})

	var okCount int32
	engine := gin.New()
	engine.Use(middleware.IdempotencyMiddleware())
	engine.POST("/x", func(c *gin.Context) {
		n := atomic.AddInt32(&okCount, 1)
		c.JSON(http.StatusOK, gin.H{"count": n})
	})
	engine.POST("/bad", func(c *gin.Context) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad"})
	})

	do := func(path, k string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(nil))
		req.Header.Set("Idempotency-Key", k)
		engine.ServeHTTP(w, req)
		return w
	}

	first := do("/x", key)
	if first.Code != 200 || okCount != 1 {
		t.Fatalf("首次请求异常: code=%d count=%d body=%s", first.Code, okCount, first.Body.String())
	}
	second := do("/x", key)
	if second.Code != 200 || okCount != 1 {
		t.Fatalf("重放不应再次执行: code=%d count=%d", second.Code, okCount)
	}
	if second.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("重放响应缺少 Idempotent-Replayed")
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("重放响应体不一致: %q vs %q", first.Body.String(), second.Body.String())
	}

	// 4xx 不缓存：同 key 重试仍会执行
	do("/bad", key)
	do("/bad", key)
	var stale int
	if err := r.Pool().QueryRow(t.Context(),
		`select count(*) from idempotency_keys where path='/bad' and user_id=''`).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("4xx 不应留下缓存，实际 %d 条", stale)
	}
}
