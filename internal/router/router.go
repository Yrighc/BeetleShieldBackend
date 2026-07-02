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

// New 创建并配置一个新的gin引擎实例
// 参数:
//   deps - 依赖项结构体，包含各种处理器和密钥
// 返回值:
//   *gin.Engine - 配置好的gin引擎实例
func New(deps Deps) *gin.Engine {
	// 创建一个新的gin引擎实例
	r := gin.New()
	// 使用中间件: 日志记录、错误恢复和跨域资源共享
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	// 健康检查接口
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 创建API v1路由组
	v1 := r.Group("/api/v1")
	{
		// 认证相关路由组
		auth := v1.Group("/auth")
		{
			// 登录接口
			auth.POST("/login", deps.AuthHandler.Login)
			// 获取当前用户信息接口，需要JWT认证
			auth.GET("/me", middleware.JWTAuth(deps.JWTSecret), deps.AuthHandler.Me)
		}
	}

	// 返回配置好的引擎实例
	return r
}
