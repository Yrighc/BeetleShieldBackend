package handler_test

import (
	"bytes"
	"context"
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
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
	"gorm.io/gorm"
)

type fakeHardeningHandlerURLStorage struct{}

type hardeningHandlerTestScope struct {
	runID string
}

func (fakeHardeningHandlerURLStorage) PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error) {
	return "https://minio.example/" + objectKey, nil
}

func newHardeningHandlerTestScope() hardeningHandlerTestScope {
	return hardeningHandlerTestScope{
		runID: fmt.Sprintf("handler-%d", time.Now().UnixNano()),
	}
}

func (s hardeningHandlerTestScope) packageNamePrefix() string {
	return "com.hardening.handler." + s.runID
}

func (s hardeningHandlerTestScope) packageName(suffix string) string {
	return s.packageNamePrefix() + "." + suffix
}

func (s hardeningHandlerTestScope) email(role string) string {
	return fmt.Sprintf("%s-%s@beetleshield.com", s.runID, role)
}

func (s hardeningHandlerTestScope) objectKey(suffix string) string {
	return "handler/" + s.runID + "/" + suffix + "/app.apk"
}

func cleanupHardeningHandlerTestData(t *testing.T, database *gorm.DB, scope hardeningHandlerTestScope) {
	t.Helper()

	database.Exec(`
		DELETE FROM hardening_logs
		WHERE task_id IN (
			SELECT hardening_tasks.id
			FROM hardening_tasks
			JOIN apps ON apps.id = hardening_tasks.app_id
			WHERE apps.package_name LIKE ?
		)
	`, scope.packageNamePrefix()+".%")
	database.Exec(`
		DELETE FROM hardening_steps
		WHERE task_id IN (
			SELECT hardening_tasks.id
			FROM hardening_tasks
			JOIN apps ON apps.id = hardening_tasks.app_id
			WHERE apps.package_name LIKE ?
		)
	`, scope.packageNamePrefix()+".%")
	database.Exec(`
		DELETE FROM hardening_tasks
		WHERE app_id IN (
			SELECT id FROM apps WHERE package_name LIKE ?
		)
	`, scope.packageNamePrefix()+".%")
	database.Unscoped().Where("package_name LIKE ?", scope.packageNamePrefix()+".%").Delete(&model.App{})
	database.Unscoped().Where("email IN ?", []string{
		scope.email("admin"),
		scope.email("developer"),
		scope.email("auditor"),
	}).Delete(&model.User{})
}

func setupHardeningRouter(t *testing.T) (*httptest.Server, string, string, string, uint, *repository.HardeningRepository, func()) {
	t.Helper()
	scope := newHardeningHandlerTestScope()

	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "hardening-handler-secret", JWTExpireHours: 1,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	cleanupHardeningHandlerTestData(t, database, scope)
	t.Cleanup(func() {
		cleanupHardeningHandlerTestData(t, database, scope)
	})

	userRepo := repository.NewUserRepository(database)
	hashed, err := hash.HashPassword("Password123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	users := []model.User{
		{
			Name:         "Hardening Admin",
			Email:        scope.email("admin"),
			PasswordHash: hashed,
			Role:         model.RoleAdmin,
			Status:       model.UserStatusActive,
		},
		{
			Name:         "Hardening Developer",
			Email:        scope.email("developer"),
			PasswordHash: hashed,
			Role:         model.RoleDeveloper,
			Status:       model.UserStatusActive,
		},
		{
			Name:         "Hardening Auditor",
			Email:        scope.email("auditor"),
			PasswordHash: hashed,
			Role:         model.RoleAuditor,
			Status:       model.UserStatusActive,
		},
	}
	for i := range users {
		if err := userRepo.Create(&users[i]); err != nil {
			t.Fatalf("create user %s: %v", users[i].Role, err)
		}
	}

	authSvc := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	adminToken, _, err := authSvc.Login(users[0].Email, "Password123!")
	if err != nil {
		t.Fatalf("admin Login() error = %v", err)
	}
	developerToken, _, err := authSvc.Login(users[1].Email, "Password123!")
	if err != nil {
		t.Fatalf("developer Login() error = %v", err)
	}
	auditorToken, _, err := authSvc.Login(users[2].Email, "Password123!")
	if err != nil {
		t.Fatalf("auditor Login() error = %v", err)
	}

	appRepo := repository.NewAppRepository(database)
	app := model.App{
		Name:        "Handler App",
		PackageName: scope.packageName("app"),
		Version:     "1.0.0",
		Tag:         model.AppTagTool,
		Status:      model.AppStatusUnprotected,
		ObjectKey:   scope.objectKey("app"),
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		UploadedBy:  users[0].ID,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	strategySvc := service.NewStrategyService(repository.NewStrategyRepository(database))
	hardeningRepo := repository.NewHardeningRepository(database)
	hardeningSvc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningHandlerURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
	)
	hardeningHandler := handler.NewHardeningHandler(hardeningSvc)

	r := router.New(router.Deps{
		JWTSecret:        cfg.JWTSecret,
		AuthHandler:      handler.NewAuthHandler(authSvc),
		HardeningHandler: hardeningHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		srv.Close()
		cleanupHardeningHandlerTestData(t, database, scope)
	}
	return srv, adminToken, developerToken, auditorToken, app.ID, hardeningRepo, cleanup
}

func TestHardeningHandler_CreateAllowsDeveloperAndRejectsAuditor(t *testing.T) {
	srv, _, developerToken, auditorToken, appID, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, err := json.Marshal(map[string]interface{}{
		"appId":                    appID,
		"strategyName":             "信息院 App 加固模板",
		"vmpRulesText":             "com.example.**",
		"enableFileIntegrityCheck": true,
		"enableProxyDetect":        true,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("developer create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("developer status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Data.Task.AppID != appID {
		t.Fatalf("created task appID = %d, want %d", created.Data.Task.AppID, appID)
	}
	if !created.Data.Task.EnableFileIntegrityCheck || !created.Data.Task.EnableProxyDetect {
		t.Fatalf("advanced flags not preserved: %+v", created.Data.Task)
	}

	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+auditorToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("auditor create request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor status = %d, want %d", resp2.StatusCode, http.StatusForbidden)
	}
}

func TestHardeningHandler_CreateReturnsConflictForDuplicateActiveTask(t *testing.T) {
	srv, _, developerToken, _, appID, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, err := json.Marshal(map[string]interface{}{"appId": appID})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+developerToken)
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
			t.Fatalf("second create status = %d, want %d", resp.StatusCode, http.StatusConflict)
		}
		resp.Body.Close()
	}
}

func TestHardeningHandler_ReadRoutesAllowAuditor(t *testing.T) {
	srv, adminToken, _, auditorToken, appID, repo, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, err := json.Marshal(map[string]interface{}{"appId": appID})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("create status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		resp.Body.Close()
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()

	taskID := created.Data.Task.ID
	stepID := created.Data.Steps[0].ID
	if err := repo.AppendLog(&model.HardeningLog{
		TaskID:  taskID,
		StepID:  &stepID,
		Level:   model.HardeningLogLevelInfo,
		Message: "handler log",
	}); err != nil {
		t.Fatalf("AppendLog() error = %v", err)
	}

	now := time.Now()
	if err := repo.MarkTaskRunning(taskID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := repo.MarkTaskCompleted(taskID, "handler/unsigned.apk", 10, "abc", "", 0, "", now); err != nil {
		t.Fatalf("MarkTaskCompleted() error = %v", err)
	}

	type routeCheck struct {
		name string
		path string
	}

	for _, tc := range []routeCheck{
		{name: "list", path: "/api/v1/hardening-tasks"},
		{name: "detail", path: fmt.Sprintf("/api/v1/hardening-tasks/%d", taskID)},
		{name: "logs", path: fmt.Sprintf("/api/v1/hardening-tasks/%d/logs?stepKey=%s", taskID, model.HardeningStepPrepareInput)},
		{name: "download", path: fmt.Sprintf("/api/v1/hardening-tasks/%d/download-url", taskID)},
		{name: "history", path: fmt.Sprintf("/api/v1/apps/%d/hardening-history", appID)},
	} {
		getReq, _ := http.NewRequest(http.MethodGet, srv.URL+tc.path, nil)
		getReq.Header.Set("Authorization", "Bearer "+auditorToken)
		getResp, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatalf("%s request: %v", tc.name, err)
		}
		if getResp.StatusCode != http.StatusOK {
			getResp.Body.Close()
			t.Fatalf("%s status = %d, want %d", tc.name, getResp.StatusCode, http.StatusOK)
		}
		getResp.Body.Close()
	}
}
