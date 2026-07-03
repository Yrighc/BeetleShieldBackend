package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
)

// RequestLogEntry is the recorder-agnostic shape RequestLog hands off; it
// deliberately doesn't import beetleshield-backend/internal/service, so
// RequestLogRecorder is implemented by *service.APIRequestLogService via
// structural typing, avoiding a middleware -> service import.
type RequestLogEntry struct {
	Method      string
	Path        string
	Status      int
	LatencyMS   int64
	ClientIP    string
	ActorUserID uint
}

type RequestLogRecorder interface {
	Record(entry RequestLogEntry)
}

// RequestLogRecorderFunc adapts a plain function to the RequestLogRecorder
// interface, mirroring http.HandlerFunc. Used by main.go to wrap
// *service.APIRequestLogService.Record (which takes a
// service.RecordAPIRequestInput, not a middleware.RequestLogEntry) without
// either package importing the other.
type RequestLogRecorderFunc func(entry RequestLogEntry)

func (f RequestLogRecorderFunc) Record(entry RequestLogEntry) { f(entry) }

// RequestLog must be registered before any subgroup's JWTAuth/RequireRole so
// that its post-c.Next() code (which needs the final response status and
// any authenticated user ID set by inner auth middleware) runs last, per
// Gin's outer-wraps-inner execution order.
func RequestLog(recorder RequestLogRecorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		recorder.Record(RequestLogEntry{
			Method:      c.Request.Method,
			Path:        c.FullPath(),
			Status:      c.Writer.Status(),
			LatencyMS:   time.Since(start).Milliseconds(),
			ClientIP:    c.ClientIP(),
			ActorUserID: c.GetUint(ContextUserIDKey),
		})
	}
}
