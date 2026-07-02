package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func setupUserRouter(t *testing.T) (*httptest.Server, string, string, func()) {
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
	adminUser := model.User{
		Name: "用户接口管理员", Email: "userhandler-admin@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(adminUser.Email)
	if err := userRepo.Create(&adminUser); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	auditorUser := model.User{
		Name: "用户接口审计员", Email: "userhandler-auditor@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAuditor, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(auditorUser.Email)
	if err := userRepo.Create(&auditorUser); err != nil {
		t.Fatalf("create auditor user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	adminToken, _, err := authService.Login(adminUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("admin Login() error = %v", err)
	}
	auditorToken, _, err := authService.Login(auditorUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("auditor Login() error = %v", err)
	}
	authHandler := handler.NewAuthHandler(authService)

	userService := service.NewUserService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		UserHandler: userHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(adminUser.Email)
		userRepo.DeleteByEmail(auditorUser.Email)
		database.Unscoped().Where("email LIKE ?", "userhandler-created-%@beetleshield.com").Delete(&model.User{})
		srv.Close()
	}
	return srv, adminToken, auditorToken, cleanup
}

func TestUserCreateListUpdateStatus_AsAdmin(t *testing.T) {
	srv, adminToken, _, cleanup := setupUserRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"name": "新建开发者", "email": "userhandler-created-1@beetleshield.com",
		"password": "Password123!", "role": "developer", "department": "研发部",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var createResp struct {
		Data model.User `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	userID := createResp.Data.ID
	if userID == 0 {
		t.Fatal("expected non-zero user ID")
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/users?role=developer", nil)
	listReq.Header.Set("Authorization", "Bearer "+adminToken)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	updateBody, _ := json.Marshal(map[string]string{"department": "安全部"})
	updateReq, _ := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/users/%d", srv.URL, userID), bytes.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", "Bearer "+adminToken)
	updateResp, err := http.DefaultClient.Do(updateReq)
	if err != nil {
		t.Fatalf("update request: %v", err)
	}
	defer updateResp.Body.Close()
	if updateResp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, want %d", updateResp.StatusCode, http.StatusOK)
	}

	statusBody, _ := json.Marshal(map[string]string{"status": "disabled"})
	statusReq, _ := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/users/%d/status", srv.URL, userID), bytes.NewReader(statusBody))
	statusReq.Header.Set("Content-Type", "application/json")
	statusReq.Header.Set("Authorization", "Bearer "+adminToken)
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatalf("status request: %v", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status update status = %d, want %d", statusResp.StatusCode, http.StatusOK)
	}
}

func TestUserRoutes_RequireAdminRole(t *testing.T) {
	srv, _, auditorToken, cleanup := setupUserRouter(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+auditorToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestUserCreate_DuplicateEmailConflict(t *testing.T) {
	srv, adminToken, _, cleanup := setupUserRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"name": "重复用户", "email": "userhandler-created-2@beetleshield.com",
		"password": "Password123!", "role": "developer",
	})

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/users", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create request %d: %v", i, err)
		}
		resp.Body.Close()
		if i == 0 && resp.StatusCode != http.StatusOK {
			t.Fatalf("first create status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if i == 1 && resp.StatusCode != http.StatusConflict {
			t.Fatalf("second create status = %d, want %d", resp.StatusCode, http.StatusConflict)
		}
	}
}
