package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS 是一个跨域资源共享(CORS)的中间件函数
// 它返回一个 gin.HandlerFunc，用于处理 HTTP 请求的跨域设置
func CORS() gin.HandlerFunc {
	// 返回一个匿名函数，该函数会被 gin 框架在处理请求时调用
	return func(c *gin.Context) {
		// 设置响应头，允许所有来源的跨域请求
		c.Header("Access-Control-Allow-Origin", "*")
		// 设置响应头，允许的 HTTP 方法
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// 设置响应头，允许的请求头字段
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")

		// 如果是 OPTIONS 请求（预检请求），直接返回状态码 204 并终止请求处理
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		// 继续处理后续的中间件和路由处理函数
		c.Next()
	}
}
