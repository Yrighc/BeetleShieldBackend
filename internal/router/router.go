package router

import (
	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
)

type Deps struct {
	JWTSecret   string
	AuthHandler *handler.AuthHandler
}

func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", deps.AuthHandler.Login)
			auth.GET("/me", middleware.JWTAuth(deps.JWTSecret), deps.AuthHandler.Me)
		}
	}

	return r
}
