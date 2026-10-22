package api

import (
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/service"
	"github.com/c1ayooo/4zreark/utils"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	userService *service.UserService
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		userService: service.NewUserService(),
	}
}

// Register handles user registration
// POST /api/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required,min=3,max=32"`
		Password string `json:"password" binding:"required,min=6,max=32"`
		Email    string `json:"email" binding:"required,email"`
		Code     string `json:"code"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	var user *models.User
	var err error
	if strings.TrimSpace(req.Code) != "" {
		user, err = h.userService.RegisterWithCode(req.Username, req.Password, req.Email, strings.TrimSpace(req.Code))
		if err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
	} else {
		user, err = h.userService.Register(req.Username, req.Password, req.Email)
		if err != nil {
			utils.Error(c, utils.ErrCodeDuplicate, err.Error())
			return
		}
	}

	utils.SuccessWithMessage(c, "注册成功", gin.H{
		"id":       user.ID.Hex(),
		"username": user.Username,
		"email":    user.Email,
	})
}

// loginAttemptLimiter 是登录失败的进程级限速器：按 IP+用户名计数，
// 15 分钟窗口内失败满 10 次锁定 15 分钟，成功登录即清零。
// 只在内存里：重启清零可接受（防在线爆破足够，PG 里已有 token 黑名单等持久状态）。
var loginAttemptLimiter = newFailureLimiter(10, 15*time.Minute)

// Login handles user login
// POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	key := c.ClientIP() + "|" + req.Username
	if loginAttemptLimiter.blocked(key) {
		utils.Error(c, utils.ErrCodeTooManyRequests, "尝试次数过多，请 15 分钟后再试")
		return
	}

	token, user, err := h.userService.Login(req.Username, req.Password)
	if err != nil {
		loginAttemptLimiter.fail(key)
		utils.Error(c, utils.ErrCodePasswordWrong, err.Error())
		return
	}
	loginAttemptLimiter.reset(key)

	utils.Success(c, gin.H{
		"token": token,
		// must_change_password=true 时前端应引导用户先去改密（后端已拦截其余接口）。
		"must_change_password": user.MustChangePassword,
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
			"avatar":   user.Avatar,
		},
	})
}

// Logout handles user logout
// POST /api/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get token from header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			token := parts[1]
			// Blacklist the token in Redis
			if err := h.userService.BlacklistToken(token); err != nil {
				// Log error but don't fail logout
				c.Set("logout_warning", "token blacklist failed")
			}
		}
	}
	utils.SuccessWithMessage(c, "登出成功", nil)
}

// GetProfile gets current user profile
// GET /api/auth/profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")

	user, err := h.userService.GetUserByID(userID.(string))
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}

	utils.Success(c, gin.H{
		"id":                   user.ID.Hex(),
		"username":             user.Username,
		"email":                user.Email,
		"phone":                user.Phone,
		"nickname":             user.Nickname,
		"role":                 user.Role,
		"avatar":               user.Avatar,
		"last_login":           user.LastLogin,
		"created_at":           user.CreatedAt,
		"must_change_password": user.MustChangePassword,
	})
}

// UpdateProfile updates current user profile
// PUT /api/auth/profile
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		Avatar   string `json:"avatar"`
		Nickname string `json:"nickname"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	updates := make(map[string]interface{})
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Phone != "" {
		updates["phone"] = req.Phone
	}
	if req.Avatar != "" {
		updates["avatar"] = req.Avatar
	}
	if req.Nickname != "" {
		updates["nickname"] = req.Nickname
	}

	if err := h.userService.UpdateUser(userID.(string), updates); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "更新成功", nil)
}

// ChangePassword changes current user password
// PUT /api/auth/password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6,max=32"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.userService.ChangePassword(userID.(string), req.OldPassword, req.NewPassword); err != nil {
		utils.Error(c, utils.ErrCodePasswordWrong, err.Error())
		return
	}

	utils.SuccessWithMessage(c, "密码修改成功", nil)
}

// RefreshToken refreshes JWT token
// POST /api/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	// 与 AuthMiddleware 同一套吊销检查：已登出（进黑名单）或版本号已失效的
	// token 不得换新，否则用户登出无法止损被窃 token。
	claims, err := utils.ParseToken(req.Token)
	if err == nil && h.userService.IsTokenRevoked(req.Token, claims.UserID, claims.Ver) {
		utils.Error(c, utils.ErrCodeTokenInvalid, "Token已失效")
		return
	}

	newToken, err := utils.RefreshToken(req.Token)
	if err != nil {
		utils.Error(c, utils.ErrCodeTokenInvalid, "Token无效或已过期")
		return
	}

	utils.Success(c, gin.H{
		"token": newToken,
	})
}
