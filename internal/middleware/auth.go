package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/pkg/jwtutil"
	"beetleshield-backend/internal/pkg/response"
)

const (
	ContextUserIDKey = "userID"
	ContextRoleKey   = "role"
)

// JWTAuth 是一个JWT认证中间件函数，用于验证请求中的JWT令牌
// 参数:
//   - secret: 用于验证JWT令牌的密钥
// 返回值:
//   - gin.HandlerFunc: Gin框架的中间件函数
func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头中获取Authorization字段
		header := c.GetHeader("Authorization")
		// 检查Authorization头是否存在且以"Bearer "开头
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			// 如果缺少或无效的授权头，返回错误响应
			response.Error(c, http.StatusUnauthorized, 40100, "missing or invalid authorization header")
			c.Abort() // 终止请求处理
			return
		}

		// 提取令牌部分，去除"Bearer "前缀
		tokenString := strings.TrimPrefix(header, "Bearer ")
		// 使用密钥解析令牌，获取声明信息
		claims, err := jwtutil.ParseToken(secret, tokenString)
		if err != nil {
			// 如果令牌无效或已过期，返回错误响应
			response.Error(c, http.StatusUnauthorized, 40101, "invalid or expired token")
			c.Abort() // 终止请求处理
			return
		}

		// 将用户ID和角色信息存储到上下文中，供后续处理使用
		c.Set(ContextUserIDKey, claims.UserID)
		c.Set(ContextRoleKey, claims.Role)
		c.Next() // 继续处理请求
	}
}
