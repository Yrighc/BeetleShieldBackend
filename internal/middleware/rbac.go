package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
)

func RequireRole(roles ...model.UserRole) gin.HandlerFunc {
	allowed := make(map[model.UserRole]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(c *gin.Context) {
		role := model.UserRole(c.GetString(ContextRoleKey))
		if !allowed[role] {
			response.Error(c, http.StatusForbidden, 40302, "insufficient permissions")
			c.Abort()
			return
		}
		c.Next()
	}
}
