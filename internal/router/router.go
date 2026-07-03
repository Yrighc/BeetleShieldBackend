package router

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
)

type Deps struct {
	JWTSecret            string
	AuthHandler          *handler.AuthHandler
	AppHandler           *handler.AppHandler
	UserHandler          *handler.UserHandler
	StrategyHandler      *handler.StrategyHandler
	HardeningHandler     *handler.HardeningHandler
	AuditHandler         *handler.AuditHandler
	APIRequestLogHandler *handler.APIRequestLogHandler
	RequestLogRecorder   middleware.RequestLogRecorder
	// StaticDir, when set, serves the frontend's built SPA (index.html +
	// assets) directly from Gin so a single container can host both the
	// API and the UI on one port — no nginx needed in front. Left empty in
	// every existing deployment/test wiring, which keeps them unaffected.
	StaticDir string
}

func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	v1.Use(middleware.RequestLog(deps.RequestLogRecorder))
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
			apps.GET("/:id/hardening-history", deps.HardeningHandler.AppHistory)
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
			strategies.GET("", deps.StrategyHandler.List)
			strategies.POST("", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.Create)
			strategies.GET("/:id", deps.StrategyHandler.Get)
			strategies.PUT("/:id", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.Update)
			strategies.DELETE("/:id", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.Delete)
		}

		hardeningTasks := v1.Group("/hardening-tasks")
		hardeningTasks.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			hardeningTasks.POST("", writeRoles, deps.HardeningHandler.Create)
			hardeningTasks.GET("", deps.HardeningHandler.List)
			hardeningTasks.GET("/overview", deps.HardeningHandler.GetOverview)
			hardeningTasks.GET("/:id", deps.HardeningHandler.Get)
			hardeningTasks.GET("/:id/logs", deps.HardeningHandler.Logs)
			hardeningTasks.GET("/:id/report", deps.HardeningHandler.GetReport)
			hardeningTasks.GET("/:id/download-url", writeRoles, deps.HardeningHandler.DownloadURL)
		}

		auditLogs := v1.Group("/audit-logs")
		auditLogs.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			auditLogs.GET("", deps.AuditHandler.List)
		}

		apiLogs := v1.Group("/api-logs")
		apiLogs.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			apiLogs.GET("", deps.APIRequestLogHandler.List)
		}
	}

	if deps.StaticDir != "" {
		r.NoRoute(spaFallback(deps.StaticDir))
	}

	return r
}

// spaFallback serves a built frontend SPA: known static files (JS/CSS/
// images) are served as-is, everything else that isn't an /api/ path falls
// back to index.html so client-side routing (e.g. /apps/42) works on a
// hard refresh. filepath.Clean on an absolute URL path can't produce a
// path outside dir, so this can't be used to escape StaticDir.
func spaFallback(dir string) gin.HandlerFunc {
	indexPath := filepath.Join(dir, "index.html")
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			response.Error(c, http.StatusNotFound, 40404, "not found")
			return
		}

		requested := filepath.Join(dir, filepath.Clean(c.Request.URL.Path))
		if info, err := os.Stat(requested); err == nil && !info.IsDir() {
			c.File(requested)
			return
		}
		c.File(indexPath)
	}
}
