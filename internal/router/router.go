package router

import (
	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
)

type Deps struct {
	JWTSecret       string
	AuthHandler     *handler.AuthHandler
	AppHandler      *handler.AppHandler
	UserHandler     *handler.UserHandler
	StrategyHandler *handler.StrategyHandler
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

		writeRoles := middleware.RequireRole(model.RoleAdmin, model.RoleDeveloper)

		apps := v1.Group("/apps")
		apps.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			apps.POST("/upload", writeRoles, deps.AppHandler.Upload)
			apps.GET("", deps.AppHandler.List)
			apps.GET("/:id", deps.AppHandler.Get)
			apps.DELETE("/:id", writeRoles, deps.AppHandler.Delete)
			apps.GET("/:id/download-url", writeRoles, deps.AppHandler.DownloadURL)
		}

		users := v1.Group("/users")
		users.Use(middleware.JWTAuth(deps.JWTSecret), middleware.RequireRole(model.RoleAdmin))
		{
			users.GET("", deps.UserHandler.List)
			users.POST("", deps.UserHandler.Create)
			users.PATCH("/:id", deps.UserHandler.Update)
			users.PATCH("/:id/status", deps.UserHandler.UpdateStatus)
		}

		strategies := v1.Group("/strategies")
		strategies.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			strategies.GET("/templates", deps.StrategyHandler.Templates)
			strategies.GET("/current", deps.StrategyHandler.GetCurrent)
			strategies.PUT("/current", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.SaveCurrent)
		}
	}

	return r
}
