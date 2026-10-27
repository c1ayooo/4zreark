package middleware

import (
	"strings"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

var userService = service.NewUserService()

// AuthMiddleware validates JWT token
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.Unauthorized(c, "请先登录")
			c.Abort()
			return
		}

		// Check Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.Unauthorized(c, "Token格式错误")
			c.Abort()
			return
		}

		tokenString := parts[1]

		claims, err := utils.ParseToken(tokenString)
		if err != nil {
			utils.Unauthorized(c, "Token无效或已过期")
			c.Abort()
			return
		}

		// 一次查询同时校验：单端登出黑名单 + 全端失效版本号。
		// 失败关闭（审计 M2）：数据层不可用/查询出错时拒绝，不视为「未吊销」。
		revoked, rerr := userService.IsTokenRevoked(tokenString, claims.UserID, claims.Ver)
		if rerr != nil {
			utils.Error(c, 503, "认证服务暂不可用，请稍后重试")
			c.Abort()
			return
		}
		if revoked {
			utils.Unauthorized(c, "Token已失效，请重新登录")
			c.Abort()
			return
		}

		// Set user info to context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("must_change_password", claims.MustChangePassword)

		c.Next()
	}
}

// mustChangePwdAllowlist 是强制改密期间唯一放行的路径：
// 看资料、改密码、登出。其余一律 403 + ErrCodeChangePwdNeeded。
var mustChangePwdAllowlist = map[string]bool{
	"/api/auth/profile":  true,
	"/api/auth/password": true,
	"/api/auth/logout":   true,
}

// MustChangePasswordGuard 强制改密：持有「默认口令未改」token 的用户只能
// 走改密闭环。标记随 JWT claims 走，这里不查库；改密成功后 SetPassword
// 清标记并 bump token_version，旧 token 全部失效，重新登录即恢复。
func MustChangePasswordGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		need, _ := c.Get("must_change_password")
		if flagged, ok := need.(bool); ok && flagged && !mustChangePwdAllowlist[c.FullPath()] {
			c.AbortWithStatusJSON(403, gin.H{
				"code":    utils.ErrCodeChangePwdNeeded,
				"message": "请先修改默认密码",
			})
			return
		}
		c.Next()
	}
}

// AdminMiddleware checks if user is admin
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			utils.Forbidden(c, "需要管理员权限")
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequirePermission 按动作权限码校验；admin 始终放行。
// 权限点来自 roles.permissions（v4 §18.2），不在前端隐藏按钮代替。
// SelfOrPermission 按资源归属放行：URL 里的 :id 与当前登录用户一致（本人）
// 或具备指定权限时通过，否则 403。用于含 PII 的用户详情等「本人可读、管理可改」的接口。
func SelfOrPermission(code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		roleName, _ := role.(string)
		uid, _ := c.Get("user_id")
		if selfID, _ := uid.(string); selfID != "" && selfID == c.Param("id") {
			c.Next()
			return
		}
		if roleName == "admin" {
			c.Next()
			return
		}
		r := repo.Default()
		if r == nil {
			utils.Error(c, utils.ErrCodeDatabaseError, "数据层未初始化")
			c.Abort()
			return
		}
		ok, err := r.Roles().HasPermission(c.Request.Context(), roleName, code)
		if err != nil || !ok {
			utils.Forbidden(c, "权限不足")
			c.Abort()
			return
		}
		c.Next()
	}
}

func RequirePermission(code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			utils.Forbidden(c, "权限不足")
			c.Abort()
			return
		}
		roleName, _ := role.(string)
		if roleName == "admin" {
			c.Next()
			return
		}
		r := repo.Default()
		if r == nil {
			utils.Error(c, utils.ErrCodeDatabaseError, "数据层未初始化")
			c.Abort()
			return
		}
		ok, err := r.Roles().HasPermission(c.Request.Context(), roleName, code)
		if err != nil || !ok {
			utils.Forbidden(c, "缺少权限："+code)
			c.Abort()
			return
		}
		c.Next()
	}
}

// RoleMiddleware checks if user has required role
func RoleMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			utils.Forbidden(c, "权限不足")
			c.Abort()
			return
		}

		roleStr := role.(string)
		for _, allowedRole := range allowedRoles {
			if roleStr == allowedRole {
				c.Next()
				return
			}
		}

		utils.Forbidden(c, "权限不足")
		c.Abort()
	}
}
