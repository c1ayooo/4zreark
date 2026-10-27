package utils

import (
	"errors"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Ver      int    `json:"ver"` // 登录态版本号，对应 users.token_version
	// MustChangePassword 强制改密标记随 token 走：中间件按 claims 拦截，
	// 不用每请求查库；改密会 bump token_version，旧 token 全部失效。
	MustChangePassword bool `json:"mcp,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken generates a new JWT token（版本号取 0，兼容旧调用）
func GenerateToken(userID, username, role string) (string, error) {
	return GenerateTokenWithVersion(userID, username, role, 0)
}

// GenerateTokenWithVersion 把 users.token_version 写进 claims，
// 改密 / 禁用后旧 token 因版本号对不上而立即失效，不依赖外部存储。
func GenerateTokenWithVersion(userID, username, role string, ver int) (string, error) {
	return GenerateTokenClaims(userID, username, role, ver, false)
}

// GenerateTokenClaims 是完整的签发入口；mustChange=true 时中间件强制改密。
func GenerateTokenClaims(userID, username, role string, ver int, mustChange bool) (string, error) {
	cfg := config.GetConfig()

	claims := Claims{
		UserID:             userID,
		Username:           username,
		Role:               role,
		Ver:                ver,
		MustChangePassword: mustChange,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(cfg.JWT.Expire) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    cfg.JWT.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWT.Secret))
}

// ParseToken parses and validates a JWT token.
// 前置校验（审计 M9，CVE-2025-30204 同形风险）：依赖库 v5.2.2 已修分段资源放大，
// 这里再做长度与段数快拒，未认证输入在进入解析器前就被丢弃。
func ParseToken(tokenString string) (*Claims, error) {
	cfg := config.GetConfig()

	if len(tokenString) == 0 || len(tokenString) > 4096 {
		return nil, errors.New("invalid token")
	}
	if strings.Count(tokenString, ".") != 2 {
		return nil, errors.New("invalid token")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(cfg.JWT.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RefreshToken refreshes a JWT token
func RefreshToken(tokenString string) (string, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return "", err
	}

	// Check if token is about to expire (within 30 minutes)
	if time.Until(claims.ExpiresAt.Time) > 30*time.Minute {
		return tokenString, nil // Token still valid, no need to refresh
	}

	return GenerateTokenClaims(claims.UserID, claims.Username, claims.Role, claims.Ver, claims.MustChangePassword)
}
