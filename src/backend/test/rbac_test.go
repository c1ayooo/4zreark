package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c1ayooo/4zreark/middleware"

	"github.com/gin-gonic/gin"
)

// 角色 → 权限码：admin 全放行，operator 只能治理/资产，viewer 只读。
func TestRolePermissions(t *testing.T) {
	r := openTestRepo(t)
	ctx := context.Background()

	cases := []struct {
		role string
		code string
		want bool
	}{
		{"admin", "source:write", true},
		{"operator", "project:write", true},
		{"operator", "run:execute", true},
		{"operator", "source:write", false},
		{"operator", "source:read", true},
		{"operator", "governance:read", true},
		{"operator", "settings:read", false},
		{"operator", "user:manage", false},
		{"viewer", "asset:read", true},
		{"viewer", "governance:read", false},
		{"viewer", "source:read", false},
		{"viewer", "project:write", false},
		{"user", "asset:read", true},
		{"user", "governance:read", false},
		{"user", "task:write", false},
	}
	for _, tc := range cases {
		got, err := r.Roles().HasPermission(ctx, tc.role, tc.code)
		if err != nil {
			t.Fatalf("HasPermission(%s,%s): %v", tc.role, tc.code, err)
		}
		if got != tc.want {
			t.Errorf("HasPermission(%s,%s)=%v want %v", tc.role, tc.code, got, tc.want)
		}
	}
	if _, err := r.Roles().HasPermission(ctx, "no-such-role", "asset:read"); err == nil {
		t.Fatal("未知角色应返回错误")
	}
}

func TestRequirePermissionMiddleware(t *testing.T) {
	_ = openTestRepo(t) // repo.Default()
	gin.SetMode(gin.TestMode)

	call := func(role, code string) int {
		engine := gin.New()
		engine.POST("/x",
			func(c *gin.Context) { c.Set("role", role) },
			middleware.RequirePermission(code),
			func(c *gin.Context) { c.Status(http.StatusOK) },
		)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		engine.ServeHTTP(w, req)
		return w.Code
	}

	if got := call("admin", "source:write"); got != http.StatusOK {
		t.Fatalf("admin 应放行，实际 %d", got)
	}
	if got := call("operator", "project:write"); got != http.StatusOK {
		t.Fatalf("operator project:write 应放行，实际 %d", got)
	}
	if got := call("operator", "source:write"); got != http.StatusForbidden {
		t.Fatalf("operator source:write 应拒绝，实际 %d", got)
	}
	if got := call("viewer", "project:write"); got != http.StatusForbidden {
		t.Fatalf("viewer project:write 应拒绝，实际 %d", got)
	}
	if got := call("operator", "governance:read"); got != http.StatusOK {
		t.Fatalf("operator governance:read 应放行，实际 %d", got)
	}
	if got := call("viewer", "governance:read"); got != http.StatusForbidden {
		t.Fatalf("viewer governance:read 应拒绝，实际 %d", got)
	}
}
