package middleware

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/c1ayooo/4zreark/config"
	"github.com/gin-gonic/gin"
)

// ForceHTTPS 的三态边界（审计 M11）：
// 默认关闭不介入；force_https 开启时明文 301 + HSTS；
// 反代已带 X-Forwarded-Proto=https 或原生 TLS 时放行并带 HSTS。
func TestForceHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config.LoadConfigRaw([]byte("server:\n  host: \"127.0.0.1\"\n  port: 8080\n"))

	run := func(forceHTTPS, tlsOn bool, forwardedProto string) *httptest.ResponseRecorder {
		config.GetConfig().Server.ForceHTTPS = forceHTTPS

		r := gin.New()
		r.Use(ForceHTTPS())
		r.GET("/api/status", func(c *gin.Context) { c.String(200, "ok") })

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/status?q=1", nil)
		if tlsOn {
			req.TLS = &tls.ConnectionState{}
		}
		if forwardedProto != "" {
			req.Header.Set("X-Forwarded-Proto", forwardedProto)
		}
		r.ServeHTTP(w, req)
		return w
	}

	// 1) 默认关闭：明文请求原样放行，不带 HSTS
	if w := run(false, false, ""); w.Code != 200 {
		t.Fatalf("默认关闭时应放行明文请求，实际 %d", w.Code)
	} else if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatalf("默认关闭时不应下发 HSTS 头")
	}

	// 2) force_https + 明文：301 到 https，保留 Host 与查询串，带 HSTS
	w := run(true, false, "")
	if w.Code != 301 {
		t.Fatalf("force_https 下明文请求应 301，实际 %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://example.com/api/status?q=1" {
		t.Fatalf("重定向目标应保留 Host 与查询串，实际 %s", loc)
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatalf("301 响应应携带 HSTS 头")
	}

	// 3) force_https + 反代已终止 TLS：放行并带 HSTS
	if w := run(true, false, "https"); w.Code != 200 {
		t.Fatalf("X-Forwarded-Proto=https 应放行，实际 %d", w.Code)
	} else if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatalf("放行响应也应携带 HSTS 头")
	}

	// 4) 原生 TLS：放行并带 HSTS
	if w := run(true, true, ""); w.Code != 200 {
		t.Fatalf("原生 TLS 请求应放行，实际 %d", w.Code)
	} else if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatalf("原生 TLS 响应应携带 HSTS 头")
	}
}
