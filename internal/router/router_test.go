package router

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newSpaTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa</html>"), 0o600); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0o600); err != nil {
		t.Fatalf("write app.js: %v", err)
	}

	r := gin.New()
	r.NoRoute(spaFallback(dir))
	return r
}

func TestSpaFallback_ServesKnownStaticFile(t *testing.T) {
	r := newSpaTestRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))

	if w.Code != http.StatusOK || w.Body.String() != "console.log(1)" {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
}

func TestSpaFallback_UnknownRouteFallsBackToIndexHTML(t *testing.T) {
	r := newSpaTestRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apps/42", nil))

	if w.Code != http.StatusOK || w.Body.String() != "<html>spa</html>" {
		t.Fatalf("status = %d, body = %q, want SPA index.html for client-side routing", w.Code, w.Body.String())
	}
}

func TestSpaFallback_UnmatchedAPIPathReturnsJSON404NotIndexHTML(t *testing.T) {
	r := newSpaTestRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if !strings.Contains(w.Body.String(), "40404") {
		t.Fatalf("body = %q, want the {code,message} envelope, not index.html", w.Body.String())
	}
}
