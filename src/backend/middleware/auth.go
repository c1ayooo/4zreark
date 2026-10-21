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

		// 一次查询同时校验：单端登出黑名单 + 全端失效版本号
		if userService.IsTokenRevoked(tokenString, claims.UserID, claims.Ver) {
			utils.Unauthorized(c, "Token已失效，请重新登录")
			c.Abort()
			return
		}

		// Set user info to context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

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
