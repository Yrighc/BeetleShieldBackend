package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/jwtutil"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func setupAuditRouter(t *testing.T) (*httptest.Server, map[model.UserRole]string, uint, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 300_000)
	marker := fmt.Sprintf("audit-handler-%d", time.Now().UnixNano())
	auditRepo := repository.NewAuditRepository(database)
	seeded := []model.AuditLog{
		{ActorUserID: actorID, ActorEmail: "audit-admin@example.com", Action: model.AuditActionAppUpload, TargetType: "app", TargetID: 1, Detail: marker, IP: marker, Success: true, CreatedAt: time.Now().Add(-3 * time.Minute)},
		{ActorUserID: actorID, ActorEmail: "audit-admin@example.com", Action: model.AuditActionLoginFailure, TargetType: "", Detail: marker, IP: marker, Success: false, CreatedAt: time.Now().Add(-2 * time.Minute)},
		{ActorUserID: actorID, ActorEmail: "audit-admin@example.com", Action: model.AuditActionStrategySave, TargetType: "strategy", TargetID: 2, Detail: marker, IP: marker, Success: true, CreatedAt: time.Now().Add(-time.Minute)},
	}
	for i := range seeded {
		if err := auditRepo.Record(&seeded[i]); err != nil {
			t.Fatalf("seed audit log: %v", err)
		}
	}

	auditService := service.NewAuditService(auditRepo)
	auditHandler := handler.NewAuditHandler(auditService)
	r := router.New(router.Deps{
		JWTSecret:    cfg.JWTSecret,
		AuditHandler: auditHandler,
	})
	srv := httptest.NewServer(r)

	tokens := map[model.UserRole]string{}
	for _, role := range []model.UserRole{model.RoleAdmin, model.RoleDeveloper, model.RoleAuditor} {
		token, err := jwtutil.GenerateToken(cfg.JWTSecret, actorID, string(role), cfg.JWTExpireHours)
		if err != nil {
			t.Fatalf("GenerateToken(%s) error = %v", role, err)
		}
		tokens[role] = token
	}

	cleanup := func() {
		database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
		srv.Close()
	}
	return srv, tokens, actorID, cleanup
}

func TestAuditLogs_AnyAuthenticatedRoleCanList(t *testing.T) {
	srv, tokens, actorID, cleanup := setupAuditRouter(t)
	defer cleanup()

	for _, role := range []model.UserRole{model.RoleAdmin, model.RoleDeveloper, model.RoleAuditor} {
		t.Run(string(role), func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/audit-logs?actorUserId=%d", srv.URL, actorID), nil)
			req.Header.Set("Authorization", "Bearer "+tokens[role])
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("audit logs request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}

			var decoded struct {
				Data struct {
					Items []model.AuditLog `json:"items"`
					Total int64            `json:"total"`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if decoded.Data.Total != 3 || len(decoded.Data.Items) != 3 {
				t.Fatalf("got len=%d total=%d, want 3/3", len(decoded.Data.Items), decoded.Data.Total)
			}
		})
	}
}

func TestAuditLogs_FiltersAndAuth(t *testing.T) {
	srv, tokens, actorID, cleanup := setupAuditRouter(t)
	defer cleanup()

	cases := []struct {
		name  string
		query string
		want  int64
	}{
		{name: "action", query: "action=app.upload", want: 1},
		{name: "target type", query: "targetType=strategy", want: 1},
		{name: "success true", query: "success=true", want: 2},
		{name: "success false", query: "success=false", want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/audit-logs?actorUserId=%d&%s", srv.URL, actorID, tc.query), nil)
			req.Header.Set("Authorization", "Bearer "+tokens[model.RoleAdmin])
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("audit logs request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			var decoded struct {
				Data struct {
					Total int64 `json:"total"`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if decoded.Data.Total != tc.want {
				t.Fatalf("total = %d, want %d", decoded.Data.Total, tc.want)
			}
		})
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/audit-logs?actorUserId=%d", srv.URL, actorID), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
