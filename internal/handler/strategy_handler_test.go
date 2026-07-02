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

func setupStrategyRouter(t *testing.T) (*httptest.Server, string, string, func()) {
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
		Name: "策略接口管理员", Email: "strategyhandler-admin@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(adminUser.Email)
	if err := userRepo.Create(&adminUser); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	developerUser := model.User{
		Name: "策略接口开发者", Email: "strategyhandler-developer@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(developerUser.Email)
	if err := userRepo.Create(&developerUser); err != nil {
		t.Fatalf("create developer user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours, nil)
	adminToken, _, err := authService.Login(adminUser.Email, "Password123!", "")
	if err != nil {
		t.Fatalf("admin Login() error = %v", err)
	}
	developerToken, _, err := authService.Login(developerUser.Email, "Password123!", "")
	if err != nil {
		t.Fatalf("developer Login() error = %v", err)
	}
	authHandler := handler.NewAuthHandler(authService)

	strategyRepo := repository.NewStrategyRepository(database)
	strategyService := service.NewStrategyService(strategyRepo, nil)
	strategyHandler := handler.NewStrategyHandler(strategyService)

	r := router.New(router.Deps{
		JWTSecret:       cfg.JWTSecret,
		AuthHandler:     authHandler,
		StrategyHandler: strategyHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(adminUser.Email)
		userRepo.DeleteByEmail(developerUser.Email)
		database.Unscoped().Where("1 = 1").Delete(&model.Strategy{})
		srv.Close()
	}
	return srv, adminToken, developerToken, cleanup
}

func TestStrategyTemplates_AnyAuthenticatedRole(t *testing.T) {
	srv, _, developerToken, cleanup := setupStrategyRouter(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies/templates", nil)
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("templates request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("templates status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var tplResp struct {
		Data map[string]model.Strategy `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tplResp); err != nil {
		t.Fatalf("decode templates response: %v", err)
	}
	if len(tplResp.Data) != 3 {
		t.Fatalf("expected 3 templates, got %d", len(tplResp.Data))
	}
}

func TestStrategySaveCurrent_AdminSucceedsThenGetCurrentReflectsIt(t *testing.T) {
	srv, adminToken, _, cleanup := setupStrategyRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"frida": true, "xposed": false, "debugger": true, "emulator": false,
		"dexLevel": "medium", "stringEncrypt": true, "resMix": false,
		"soShell": "aes", "soStrength": 70, "targetSos": []string{"libunity.so"},
		"rootDetect": true, "signature": true, "antiHook": true, "resEncrypt": false,
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/strategies/current", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	getReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies/current", nil)
	getReq.Header.Set("Authorization", "Bearer "+adminToken)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get current request: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get current status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}

	var currentResp struct {
		Data model.Strategy `json:"data"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&currentResp); err != nil {
		t.Fatalf("decode get current response: %v", err)
	}
	if currentResp.Data.DexLevel != model.DexLevelMedium || currentResp.Data.SoStrength != 70 {
		t.Errorf("GetCurrent() after save did not reflect saved values: %+v", currentResp.Data)
	}
}

func TestStrategySaveCurrent_RequiresAdminRole(t *testing.T) {
	srv, _, developerToken, cleanup := setupStrategyRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"dexLevel": "low", "soShell": "none", "soStrength": 30,
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/strategies/current", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("save status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}
