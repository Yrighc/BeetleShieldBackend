package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/jwtutil"
)

func setupRBACRouter(secret string, allowedRoles ...model.UserRole) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JWTAuth(secret))
	r.GET("/protected", RequireRole(allowedRoles...), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRequireRole_AllowedRolePasses(t *testing.T) {
	secret := "test-secret"
	r := setupRBACRouter(secret, model.RoleAdmin)
	token, err := jwtutil.GenerateToken(secret, 1, string(model.RoleAdmin), 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body=%s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRequireRole_DisallowedRoleForbidden(t *testing.T) {
	secret := "test-secret"
	r := setupRBACRouter(secret, model.RoleAdmin)
	token, err := jwtutil.GenerateToken(secret, 1, string(model.RoleAuditor), 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d, body=%s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestRequireRole_MissingTokenUnauthorized(t *testing.T) {
	r := setupRBACRouter("test-secret", model.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireRole_MultipleAllowedRoles(t *testing.T) {
	secret := "test-secret"
	r := setupRBACRouter(secret, model.RoleAdmin, model.RoleDeveloper)
	token, err := jwtutil.GenerateToken(secret, 2, string(model.RoleDeveloper), 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
