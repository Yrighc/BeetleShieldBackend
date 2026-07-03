package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

// setupAPIRequestLogRouter wires a full router.New(...) including the real
// RequestLog middleware (registered first on /api/v1, per the plan) so that
// every request made against the returned server is actually recorded into
// api_request_logs, end to end.
func setupAPIRequestLogRouter(t *testing.T) (*httptest.Server, string, string, func()) {
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

	userRepo := repository.NewUserRepository(database)
	hashed, _ := hash.HashPassword("Password123!")
	testUser := model.User{
		Name: "API日志接口测试用户", Email: "apirequestlog-handler-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(testUser.Email)
	if err := userRepo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	auditRepo := repository.NewAuditRepository(database)
	auditService := service.NewAuditService(auditRepo)
	auditHandler := handler.NewAuditHandler(auditService)

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours, auditService)
	authHandler := handler.NewAuthHandler(authService)

	apiRequestLogRepo := repository.NewAPIRequestLogRepository(database)
	apiRequestLogService := service.NewAPIRequestLogService(apiRequestLogRepo)
	apiRequestLogHandler := handler.NewAPIRequestLogHandler(apiRequestLogService)
	requestLogRecorder := middleware.RequestLogRecorderFunc(func(entry middleware.RequestLogEntry) {
		apiRequestLogService.Record(service.RecordAPIRequestInput{
			Method: entry.Method, Path: entry.Path, Status: entry.Status,
			LatencyMS: entry.LatencyMS, ClientIP: entry.ClientIP, ActorUserID: entry.ActorUserID,
		})
	})

	r := router.New(router.Deps{
		JWTSecret:            cfg.JWTSecret,
		AuthHandler:          authHandler,
		AuditHandler:         auditHandler,
		APIRequestLogHandler: apiRequestLogHandler,
		RequestLogRecorder:   requestLogRecorder,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(testUser.Email)
		srv.Close()
	}
	return srv, testUser.Email, "Password123!", cleanup
}

func TestAPIRequestLogs_RecordsAndListsPriorRequests(t *testing.T) {
	srv, email, password, cleanup := setupAPIRequestLogRouter(t)
	defer cleanup()

	// 1. Unauthenticated login request (no ActorUserID expected).
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	loginReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	var loginDecoded struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginDecoded); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	token := loginDecoded.Data.Token
	if token == "" {
		t.Fatalf("expected a token from login response")
	}

	// 2. Authenticated GET against a JWTAuth-protected route (audit-logs),
	// which sets ContextUserIDKey via JWTAuth before RequestLog's deferred
	// recording code observes it.
	auditReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/audit-logs", nil)
	auditReq.Header.Set("Authorization", "Bearer "+token)
	auditResp, err := http.DefaultClient.Do(auditReq)
	if err != nil {
		t.Fatalf("audit logs request: %v", err)
	}
	defer auditResp.Body.Close()
	if auditResp.StatusCode != http.StatusOK {
		t.Fatalf("audit logs status = %d, want %d", auditResp.StatusCode, http.StatusOK)
	}

	// Give the fire-and-forget-but-synchronous middleware a beat (it's
	// actually synchronous within the request/response cycle, but the
	// api-logs GET below is itself a new request that must be issued after
	// the above two responses have fully returned).
	time.Sleep(50 * time.Millisecond)

	// 3. Now list api-logs (itself authenticated) and confirm the prior
	// requests show up with correct method/path/status.
	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/api-logs?pageSize=50", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("api-logs request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("api-logs status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	var listDecoded struct {
		Data struct {
			Items []model.APIRequestLog `json:"items"`
			Total int64                 `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listDecoded); err != nil {
		t.Fatalf("decode api-logs response: %v", err)
	}

	var sawLogin, sawAudit bool
	for _, item := range listDecoded.Data.Items {
		if item.Method == http.MethodPost && item.Path == "/api/v1/auth/login" && item.Status == http.StatusOK {
			sawLogin = true
		}
		if item.Method == http.MethodGet && item.Path == "/api/v1/audit-logs" && item.Status == http.StatusOK {
			sawAudit = true
			if item.ActorUserID == 0 {
				t.Errorf("expected ActorUserID to be set for authenticated GET /audit-logs, got 0")
			}
		}
	}
	if !sawLogin {
		t.Errorf("expected to find a recorded POST /api/v1/auth/login entry, items=%+v", listDecoded.Data.Items)
	}
	if !sawAudit {
		t.Errorf("expected to find a recorded GET /api/v1/audit-logs entry, items=%+v", listDecoded.Data.Items)
	}
}
