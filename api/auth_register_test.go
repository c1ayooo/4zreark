package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/config"
	"github.com/gin-gonic/gin"
)

// 安全审计 H1 的回归测试：注册默认关闭——空注册码必须在触碰数据层之前被拒绝；
// 显式开启（ZRE_ALLOW_PUBLIC_REGISTRATION / 配置）后才走公开注册分支。
// 不依赖数据库：默认关闭路径在校验处即返回。
func TestRegisterRequiresCodeByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config.LoadConfigRaw([]byte("server:\n  host: \"127.0.0.1\"\n  port: 8080\nauth:\n  allow_public_registration: false\n"))

	r := gin.New()
	h := NewAuthHandler()
	r.POST("/api/auth/register", h.Register)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/register", strings.NewReader(`{"username":"attacker1","password":"password123","email":"a@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	// 业务层以 code=1003（Forbidden）+「注册码必填」拒绝；关键是不能走进公开注册分支。
	if !strings.Contains(w.Body.String(), "注册码必填") {
		t.Fatalf("应提示注册码必填: %s", w.Body.String())
	}
}

func TestRegisterAllowsWhenPublicRegistrationEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// 开启公开注册：空码分支放行（后续触库，数据库未初始化时返回错误——
	// 关键断言是「不再被注册码校验拦住」，错误不再是"注册码必填"）。
	config.LoadConfigRaw([]byte("server:\n  host: \"127.0.0.1\"\n  port: 8080\nauth:\n  allow_public_registration: true\n"))
	config.GetConfig().Auth.AllowPublicRegistration = true

	r := gin.New()
	h := NewAuthHandler()
	r.POST("/api/auth/register", h.Register)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/register", strings.NewReader(`{"username":"publicuser1","password":"password123","email":"p@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), "注册码必填") {
		t.Fatalf("公开注册开启后不应被注册码校验拦截: %s", w.Body.String())
	}
}
