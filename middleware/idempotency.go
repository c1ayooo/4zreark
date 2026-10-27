package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

const (
	idempotencyHeader = "Idempotency-Key"
	maxReplayBytes    = 512 * 1024
)

// IdempotencyMiddleware 对带 Idempotency-Key 的写请求做 24h 去重（PG 存储）。
// - 同 key 首次请求正常执行，成功后缓存响应；
// - 重放直接返回缓存，不重复产生副作用；
// - 首个请求仍在处理时返回冲突；
// - 5xx / 4xx 不缓存，允许客户端修正后重试。
func IdempotencyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			c.Next()
			return
		}
		// 审计 M5：一次性秘密端点禁用响应缓存——「只显示一次」的 API Key、
		// 节点 token、注册码不能以明文落库或经重放再返回。
		path := c.Request.URL.Path
		for _, prefix := range secretEndpointPrefixes {
			if strings.HasPrefix(path, prefix) {
				c.Next()
				return
			}
		}
		rawKey := strings.TrimSpace(c.GetHeader(idempotencyHeader))
		if rawKey == "" {
			c.Next()
			return
		}
		if len(rawKey) < 8 || len(rawKey) > 200 {
			utils.BadRequest(c, "Idempotency-Key 长度需在 8..200")
			c.Abort()
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/mcp") {
			c.Next()
			return
		}
		r := repo.Default()
		if r == nil {
			c.Next()
			return
		}
		userID := c.GetString("user_id")
		sum := sha256.Sum256([]byte(userID + "|" + method + "|" + c.Request.URL.Path + "|" + rawKey))
		key := hex.EncodeToString(sum[:])

		rec, reserved, err := r.Idempotency().Reserve(c.Request.Context(), key, userID, method, c.Request.URL.Path,
			24*time.Hour)
		if err != nil {
			utils.Error(c, utils.ErrCodeDatabaseError, "幂等键处理失败")
			c.Abort()
			return
		}
		if !reserved {
			if rec.Processing {
				utils.Error(c, utils.ErrCodeDuplicate, "相同 Idempotency-Key 的请求正在处理中")
				c.Abort()
				return
			}
			c.Header("Idempotent-Replayed", "true")
			ct := rec.ContentType
			if ct == "" {
				ct = "application/json"
			}
			c.Data(rec.Status, ct, rec.Body)
			c.Abort()
			return
		}

		cw := &captureWriter{ResponseWriter: c.Writer}
		c.Writer = cw
		c.Next()

		status := cw.Status()
		if status < 200 || status >= 300 || cw.overflow {
			_ = r.Idempotency().Release(c.Request.Context(), key)
			return
		}
		_ = r.Idempotency().Complete(c.Request.Context(), key, status, c.Writer.Header().Get("Content-Type"), cw.body.Bytes())
	}
}

type captureWriter struct {
	gin.ResponseWriter
	body     bytes.Buffer
	status   int
	overflow bool
}

func (w *captureWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if !w.overflow {
		if w.body.Len()+len(b) > maxReplayBytes {
			w.overflow = true
		} else {
			w.body.Write(b)
		}
	}
	return w.ResponseWriter.Write(b)
}

func (w *captureWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *captureWriter) Status() int {
	if w.status == 0 {
		return 200
	}
	return w.status
}

// secretEndpointPrefixes 是响应体含一次性秘密、禁止幂等缓存的端点前缀（审计 M5）。
// 重放这些请求返回 409/重新执行，绝不从缓存回放秘密。
var secretEndpointPrefixes = []string{
	"/api/api-keys",          // CreatedAPIKey.Key 明文只显示一次
	"/api/nodes/enroll",      // EnrollNode 节点 token 只显示一次
	"/api/registration-codes", // 注册码明文
}
