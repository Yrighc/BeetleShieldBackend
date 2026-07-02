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

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			response.Error(c, http.StatusUnauthorized, 40100, "missing or invalid authorization header")
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(header, "Bearer ")
		claims, err := jwtutil.ParseToken(secret, tokenString)
		if err != nil {
			response.Error(c, http.StatusUnauthorized, 40101, "invalid or expired token")
			c.Abort()
			return
		}

		c.Set(ContextUserIDKey, claims.UserID)
		c.Set(ContextRoleKey, claims.Role)
		c.Next()
	}
}
