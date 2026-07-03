package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakeRequestLogRecorder struct {
	entries []RequestLogEntry
}

func (f *fakeRequestLogRecorder) Record(entry RequestLogEntry) {
	f.entries = append(f.entries, entry)
}

func TestRequestLog_CapturesMethodAndStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &fakeRequestLogRecorder{}

	r := gin.New()
	r.Use(RequestLog(recorder))
	r.GET("/dummy", func(c *gin.Context) {
		c.JSON(http.StatusTeapot, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/dummy", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTeapot)
	}
	if len(recorder.entries) != 1 {
		t.Fatalf("recorded entries = %d, want 1", len(recorder.entries))
	}
	entry := recorder.entries[0]
	if entry.Method != http.MethodGet {
		t.Errorf("Method = %q, want %q", entry.Method, http.MethodGet)
	}
	if entry.Path != "/dummy" {
		t.Errorf("Path = %q, want %q", entry.Path, "/dummy")
	}
	if entry.Status != http.StatusTeapot {
		t.Errorf("Status = %d, want %d", entry.Status, http.StatusTeapot)
	}
}

func TestRequestLog_NilRecorderIsNoop(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RequestLog(nil))
	r.GET("/dummy", func(c *gin.Context) {
		c.JSON(http.StatusAccepted, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/dummy", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusAccepted)
	}
}

// TestRequestLog_SeesActorUserIDSetByInnerMiddleware proves that RequestLog's
// post-c.Next() recording code runs *after* any auth middleware registered
// further down the chain has already set ContextUserIDKey — this is the
// "outer middleware's post-c.Next() code runs last" behavior the plan
// depends on for the real JWTAuth case.
func TestRequestLog_SeesActorUserIDSetByInnerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &fakeRequestLogRecorder{}
	const wantUserID = uint(42)

	r := gin.New()
	r.Use(RequestLog(recorder))
	r.Use(func(c *gin.Context) {
		c.Set(ContextUserIDKey, wantUserID)
		c.Next()
	})
	r.GET("/dummy", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/dummy", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if len(recorder.entries) != 1 {
		t.Fatalf("recorded entries = %d, want 1", len(recorder.entries))
	}
	if got := recorder.entries[0].ActorUserID; got != wantUserID {
		t.Errorf("ActorUserID = %d, want %d", got, wantUserID)
	}
}
