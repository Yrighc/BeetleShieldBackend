package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func setupAuthRouter(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	hashed, _ := hash.HashPassword("Password123!")
	testUser := model.User{
		Name: "接口测试用户", Email: "handler-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(testUser.Email)
	if err := userRepo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours, nil)
	authHandler := handler.NewAuthHandler(authService)
	r := router.New(router.Deps{JWTSecret: cfg.JWTSecret, AuthHandler: authHandler})

	srv := httptest.NewServer(r)
	cleanup := func() {
		userRepo.DeleteByEmail(testUser.Email)
		srv.Close()
	}
	return srv, cleanup
}

func TestLoginAndMe(t *testing.T) {
	srv, cleanup := setupAuthRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"email":    "handler-test@beetleshield.com",
		"password": "Password123!",
	})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var loginResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if loginResp.Data.Token == "" {
		t.Fatal("expected non-empty token")
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Data.Token)
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /auth/me error = %v", err)
	}
	defer meResp.Body.Close()
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", meResp.StatusCode, http.StatusOK)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	srv, cleanup := setupAuthRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"email":    "handler-test@beetleshield.com",
		"password": "wrong-password",
	})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
