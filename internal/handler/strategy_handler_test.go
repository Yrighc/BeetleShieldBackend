package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	database.Unscoped().Where("1 = 1").Delete(&model.Strategy{})

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

func TestStrategyCRUD_AdminSucceedsAndDeveloperCanRead(t *testing.T) {
	srv, adminToken, developerToken, cleanup := setupStrategyRouter(t)
	defer cleanup()

	createBody, _ := json.Marshal(map[string]interface{}{
		"name": "数信学院加固策略", "description": "高强度配置",
		"frida": true, "xposed": true, "debugger": true, "emulator": false,
		"dexLevel": "high", "stringEncrypt": true, "resMix": true,
		"soShell": "vmp", "soStrength": 90, "targetSos": []string{"libnative-lib.so"},
		"rootDetect": true, "signature": true, "antiHook": true, "resEncrypt": true,
	})
	createReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/strategies", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer "+adminToken)
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want %d", createResp.StatusCode, http.StatusOK)
	}
	var createPayload struct {
		Data model.Strategy `json:"data"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&createPayload); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createPayload.Data.ID == 0 || createPayload.Data.Name != "数信学院加固策略" || createPayload.Data.IsDefault {
		t.Fatalf("created strategy = %+v", createPayload.Data)
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies?search=数信", nil)
	listReq.Header.Set("Authorization", "Bearer "+developerToken)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}
	var listPayload struct {
		Data struct {
			Items []model.Strategy `json:"items"`
			Total int64            `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listPayload.Data.Total != 1 || len(listPayload.Data.Items) != 1 {
		t.Fatalf("list payload = %+v", listPayload.Data)
	}

	getReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies/"+strconv.Itoa(int(createPayload.Data.ID)), nil)
	getReq.Header.Set("Authorization", "Bearer "+developerToken)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}

	updateBody, _ := json.Marshal(map[string]interface{}{
		"name": "数信学院兼容策略", "description": "兼容性优先",
		"dexLevel": "low", "soShell": "none", "soStrength": 30, "signature": true,
	})
	updateReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/strategies/"+strconv.Itoa(int(createPayload.Data.ID)), bytes.NewReader(updateBody))
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

	deleteReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/strategies/"+strconv.Itoa(int(createPayload.Data.ID)), nil)
	deleteReq.Header.Set("Authorization", "Bearer "+adminToken)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want %d", deleteResp.StatusCode, http.StatusOK)
	}
}

func TestStrategyCRUD_RequiresAdminForWrites(t *testing.T) {
	srv, _, developerToken, cleanup := setupStrategyRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"name": "开发者不可写策略", "dexLevel": "low", "soShell": "none", "soStrength": 30,
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/strategies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("developer create status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestStrategyCRUD_DuplicateAndMissingErrors(t *testing.T) {
	srv, adminToken, _, cleanup := setupStrategyRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"name": "重复策略", "dexLevel": "low", "soShell": "none", "soStrength": 30,
	})
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/strategies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create request %d: %v", i+1, err)
		}
		if i == 0 && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("first create status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if i == 1 && resp.StatusCode != http.StatusConflict {
			resp.Body.Close()
			t.Fatalf("duplicate create status = %d, want %d", resp.StatusCode, http.StatusConflict)
		}
		resp.Body.Close()
	}

	missingReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies/99999999", nil)
	missingReq.Header.Set("Authorization", "Bearer "+adminToken)
	missingResp, err := http.DefaultClient.Do(missingReq)
	if err != nil {
		t.Fatalf("missing get request: %v", err)
	}
	defer missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing get status = %d, want %d", missingResp.StatusCode, http.StatusNotFound)
	}
}

func TestStrategyCurrentRouteStillWinsOverIDRoute(t *testing.T) {
	srv, adminToken, _, cleanup := setupStrategyRouter(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies/current", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("current request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("current status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var currentResp struct {
		Data model.Strategy `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&currentResp); err != nil {
		t.Fatalf("decode current response: %v", err)
	}
	if currentResp.Data.Name != service.DefaultStrategyName || !currentResp.Data.IsDefault {
		t.Fatalf("current route returned unexpected data: %+v", currentResp.Data)
	}
}
