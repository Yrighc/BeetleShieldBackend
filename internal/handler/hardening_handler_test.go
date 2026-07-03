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
	database.Unscoped().Where("updated_by = ? OR created_by = ?", uint(515151), uint(515151)).Delete(&model.Strategy{})
	database.Exec(`
		DELETE FROM audit_logs
		WHERE actor_user_id IN (
			SELECT id FROM users WHERE email IN (?, ?, ?)
		)
	`, scope.email("admin"), scope.email("developer"), scope.email("auditor"))
	database.Unscoped().Where("email IN ?", []string{
		scope.email("admin"),
		scope.email("developer"),
		scope.email("auditor"),
	}).Delete(&model.User{})
}

func setupHardeningRouter(t *testing.T) (*httptest.Server, string, string, string, uint, *repository.HardeningRepository, *repository.AuditRepository, *repository.StrategyRepository, func()) {
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

	auditRepo := repository.NewAuditRepository(database)
	auditService := service.NewAuditService(auditRepo)

	authSvc := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours, auditService)
	adminToken, _, err := authSvc.Login(users[0].Email, "Password123!", "")
	if err != nil {
		t.Fatalf("admin Login() error = %v", err)
	}
	developerToken, _, err := authSvc.Login(users[1].Email, "Password123!", "")
	if err != nil {
		t.Fatalf("developer Login() error = %v", err)
	}
	auditorToken, _, err := authSvc.Login(users[2].Email, "Password123!", "")
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

	strategyRepo := repository.NewStrategyRepository(database)
	strategySvc := service.NewStrategyService(strategyRepo, auditService)
	hardeningRepo := repository.NewHardeningRepository(database)
	hardeningSvc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningHandlerURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		auditService,
		"BeetleShield Engine v2.4.1",
	)
	dashboardSvc := service.NewDashboardService(hardeningRepo, appRepo, "BeetleShield Engine v2.4.1")
	hardeningHandler := handler.NewHardeningHandler(hardeningSvc, dashboardSvc)

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
	return srv, adminToken, developerToken, auditorToken, app.ID, hardeningRepo, auditRepo, strategyRepo, cleanup
}

func TestHardeningHandler_CreateAllowsDeveloperAndRejectsAuditor(t *testing.T) {
	srv, _, developerToken, auditorToken, appID, _, auditRepo, _, cleanup := setupHardeningRouter(t)
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

	createLog := findAuditLogForTarget(t, auditRepo, string(model.AuditActionHardeningCreate), "hardening_task", created.Data.Task.ID)
	if createLog.ActorUserID == 0 {
		t.Fatal("hardening_task.create audit entry has zero ActorUserID: the authenticated caller's ID from the JWT never reached the audit row")
	}
	if createLog.IP != "127.0.0.1" {
		t.Fatalf("hardening_task.create audit entry IP = %q, want the real client IP as seen by the HTTP server", createLog.IP)
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

func TestHardeningHandler_CreateUsesStrategyID(t *testing.T) {
	srv, _, developerToken, _, appID, _, _, strategyRepo, cleanup := setupHardeningRouter(t)
	defer cleanup()

	strategy := &model.Strategy{
		Name: "数信学院加固策略", DexLevel: model.DexLevelMedium,
		SoShell: model.SoShellAES, SoStrength: 70,
		RootDetect: true, Signature: true,
		CreatedBy: 515151, UpdatedBy: 515151,
	}
	if err := strategyRepo.Create(strategy); err != nil {
		t.Fatalf("create strategy: %v", err)
	}

	body, err := json.Marshal(map[string]interface{}{
		"appId": appID, "strategyId": strategy.ID,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Data.Task.StrategyName != "数信学院加固策略" {
		t.Fatalf("strategy name = %q", created.Data.Task.StrategyName)
	}
	if created.Data.Task.StrategySnapshot.DexLevel != model.DexLevelMedium || !created.Data.Task.StrategySnapshot.RootDetect {
		t.Fatalf("strategy snapshot = %+v", created.Data.Task.StrategySnapshot)
	}
}

func TestHardeningHandler_CreateReturnsNotFoundForMissingStrategyID(t *testing.T) {
	srv, _, developerToken, _, appID, _, _, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, err := json.Marshal(map[string]interface{}{
		"appId": appID, "strategyId": 99999999,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHardeningHandler_CreateReturnsConflictForDuplicateActiveTask(t *testing.T) {
	srv, _, developerToken, _, appID, _, _, _, cleanup := setupHardeningRouter(t)
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
	srv, adminToken, _, auditorToken, appID, repo, _, _, cleanup := setupHardeningRouter(t)
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
	if err := repo.CompleteTaskForApp(taskID, "handler/unsigned.apk", 10, "abc", "", 0, "", now, model.RiskLevelLow); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	type routeCheck struct {
		name string
		path string
	}

	for _, tc := range []routeCheck{
		{name: "list", path: "/api/v1/hardening-tasks"},
		{name: "detail", path: fmt.Sprintf("/api/v1/hardening-tasks/%d", taskID)},
		{name: "logs", path: fmt.Sprintf("/api/v1/hardening-tasks/%d/logs?stepKey=%s", taskID, model.HardeningStepPrepareInput)},
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

func TestHardeningHandler_GetReportRequiresCompletedTask(t *testing.T) {
	srv, _, developerToken, _, appID, _, _, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"appId": appID})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()

	reportReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/hardening-tasks/%d/report", srv.URL, created.Data.Task.ID), nil)
	reportReq.Header.Set("Authorization", "Bearer "+developerToken)
	reportResp, err := http.DefaultClient.Do(reportReq)
	if err != nil {
		t.Fatalf("report request: %v", err)
	}
	defer reportResp.Body.Close()
	if reportResp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want %d", reportResp.StatusCode, http.StatusConflict)
	}
}

func TestHardeningHandler_GetReportUnknownTask(t *testing.T) {
	srv, _, developerToken, _, _, _, _, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/hardening-tasks/999999999/report", nil)
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("report request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHardeningHandler_GetReportOnCompletedTaskAllowsAuditor(t *testing.T) {
	srv, _, developerToken, auditorToken, appID, hardeningRepo, _, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"appId": appID})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()

	now := time.Now()
	if err := hardeningRepo.MarkTaskRunning(created.Data.Task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := hardeningRepo.CompleteTaskForApp(created.Data.Task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", now, model.RiskLevelLow); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	reportReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/hardening-tasks/%d/report", srv.URL, created.Data.Task.ID), nil)
	reportReq.Header.Set("Authorization", "Bearer "+auditorToken)
	reportResp, err := http.DefaultClient.Do(reportReq)
	if err != nil {
		t.Fatalf("report request: %v", err)
	}
	defer reportResp.Body.Close()
	if reportResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", reportResp.StatusCode, http.StatusOK)
	}

	var got struct {
		Data service.HardeningReport `json:"data"`
	}
	if err := json.NewDecoder(reportResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode report response: %v", err)
	}
	if got.Data.Artifact.FileName != "signed.apk" {
		t.Fatalf("Artifact.FileName = %q, want signed.apk", got.Data.Artifact.FileName)
	}
	if len(got.Data.Dimensions) != 5 {
		t.Fatalf("len(Dimensions) = %d, want 5", len(got.Data.Dimensions))
	}
	if len(got.Data.Checklist) != 6 {
		t.Fatalf("len(Checklist) = %d, want 6", len(got.Data.Checklist))
	}
}

// TestHardeningHandler_DownloadURLRequiresAdminOrDeveloperRole guards against
// a regression of the download-url route's RBAC: it must match the app
// download-url route (admin/developer only, per the frontend's documented
// permission matrix for "下载加固交付包") rather than being open to every
// authenticated role like the other read-only hardening endpoints.
func TestHardeningHandler_DownloadURLRequiresAdminOrDeveloperRole(t *testing.T) {
	srv, adminToken, developerToken, auditorToken, appID, repo, auditRepo, _, cleanup := setupHardeningRouter(t)
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
	now := time.Now()
	if err := repo.MarkTaskRunning(taskID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := repo.CompleteTaskForApp(taskID, "handler/rbac-unsigned.apk", 10, "abc", "", 0, "", now, model.RiskLevelLow); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	downloadPath := fmt.Sprintf("/api/v1/hardening-tasks/%d/download-url", taskID)

	auditorReq, _ := http.NewRequest(http.MethodGet, srv.URL+downloadPath, nil)
	auditorReq.Header.Set("Authorization", "Bearer "+auditorToken)
	auditorResp, err := http.DefaultClient.Do(auditorReq)
	if err != nil {
		t.Fatalf("auditor download request: %v", err)
	}
	defer auditorResp.Body.Close()
	if auditorResp.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor download status = %d, want %d", auditorResp.StatusCode, http.StatusForbidden)
	}

	if logs, _, err := auditRepo.List(repository.AuditListFilter{Action: string(model.AuditActionHardeningDownload), TargetType: "hardening_task"}); err != nil {
		t.Fatalf("List() audit error = %v", err)
	} else {
		for _, l := range logs {
			if l.TargetID == taskID {
				t.Fatalf("a rejected (403) download attempt must not produce an audit entry, found: %+v", l)
			}
		}
	}

	seenActors := map[uint]bool{}
	for _, token := range []string{adminToken, developerToken} {
		getReq, _ := http.NewRequest(http.MethodGet, srv.URL+downloadPath, nil)
		getReq.Header.Set("Authorization", "Bearer "+token)
		getResp, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatalf("download request: %v", err)
		}
		if getResp.StatusCode != http.StatusOK {
			getResp.Body.Close()
			t.Fatalf("download status = %d, want %d", getResp.StatusCode, http.StatusOK)
		}
		getResp.Body.Close()
	}

	logs, _, err := auditRepo.List(repository.AuditListFilter{Action: string(model.AuditActionHardeningDownload), TargetType: "hardening_task"})
	if err != nil {
		t.Fatalf("List() audit error = %v", err)
	}
	for _, l := range logs {
		if l.TargetID != taskID {
			continue
		}
		if l.IP != "127.0.0.1" {
			t.Fatalf("download audit entry IP = %q, want the real client IP as seen by the HTTP server", l.IP)
		}
		seenActors[l.ActorUserID] = true
	}
	if len(seenActors) != 2 {
		t.Fatalf("distinct actors recorded for the two successful downloads = %d, want 2 (admin and developer must each land their own audit row)", len(seenActors))
	}
}

func TestHardeningHandler_GetOverviewReturnsAggregatedData(t *testing.T) {
	srv, _, developerToken, _, appID, _, _, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"appId": appID})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp.Body.Close()

	// Requesting the literal path "overview" also proves this route isn't
	// shadowed by GET /:id (which would otherwise fail to parse "overview"
	// as a uint and return 400, not 200).
	overviewReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/hardening-tasks/overview", nil)
	overviewReq.Header.Set("Authorization", "Bearer "+developerToken)
	overviewResp, err := http.DefaultClient.Do(overviewReq)
	if err != nil {
		t.Fatalf("overview request: %v", err)
	}
	defer overviewResp.Body.Close()
	if overviewResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", overviewResp.StatusCode, http.StatusOK)
	}

	var got struct {
		Data service.DashboardOverview `json:"data"`
	}
	if err := json.NewDecoder(overviewResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode overview response: %v", err)
	}
	if len(got.Data.HourlyTrend) != 24 {
		t.Fatalf("len(HourlyTrend) = %d, want 24", len(got.Data.HourlyTrend))
	}
	if got.Data.SystemStatus.EngineVersion != "BeetleShield Engine v2.4.1" {
		t.Fatalf("SystemStatus.EngineVersion = %q", got.Data.SystemStatus.EngineVersion)
	}
}
