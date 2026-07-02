package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func setupFullRouter(t *testing.T) (*httptest.Server, string, string, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
		MaxUploadSizeMB: 10,
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
		Name: "应用接口测试用户", Email: "apphandler-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(testUser.Email)
	if err := userRepo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	auditorUser := model.User{
		Name: "应用接口审计员", Email: "apphandler-auditor@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAuditor, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(auditorUser.Email)
	if err := userRepo.Create(&auditorUser); err != nil {
		t.Fatalf("create auditor user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	token, _, err := authService.Login(testUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	auditorToken, _, err := authService.Login(auditorUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("auditor Login() error = %v", err)
	}
	authHandler := handler.NewAuthHandler(authService)

	st, err := storage.NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := st.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v", err)
	}
	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)
	appService := service.NewAppService(appRepo, hardeningRepo, st, cfg.MaxUploadSizeMB)
	appHandler := handler.NewAppHandler(appService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		AppHandler:  appHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(testUser.Email)
		userRepo.DeleteByEmail(auditorUser.Email)
		database.Unscoped().Where("package_name LIKE ?", "com.handlertest.%").Delete(&model.App{})
		srv.Close()
	}
	return srv, token, auditorToken, cleanup
}

func TestAppUploadListGetDownloadDelete(t *testing.T) {
	srv, token, _, cleanup := setupFullRouter(t)
	defer cleanup()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("tag", "tool"); err != nil {
		t.Fatalf("WriteField(tag): %v", err)
	}
	if err := w.WriteField("packageName", "com.handlertest.demo"); err != nil {
		t.Fatalf("WriteField(packageName): %v", err)
	}
	if err := w.WriteField("version", "1.0.0"); err != nil {
		t.Fatalf("WriteField(version): %v", err)
	}
	part, err := w.CreateFormFile("file", "demo.aab")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write([]byte("fake aab content for handler test")); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/apps/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var uploadResp struct {
		Data model.App `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	appID := uploadResp.Data.ID
	if appID == 0 {
		t.Fatal("expected non-zero app ID")
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/apps?tag=tool", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	getReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/apps/%d", srv.URL, appID), nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}

	dlReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/apps/%d/download-url", srv.URL, appID), nil)
	dlReq.Header.Set("Authorization", "Bearer "+token)
	dlResp, err := http.DefaultClient.Do(dlReq)
	if err != nil {
		t.Fatalf("download-url request: %v", err)
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		t.Fatalf("download-url status = %d, want %d", dlResp.StatusCode, http.StatusOK)
	}

	delReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/apps/%d", srv.URL, appID), nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want %d", delResp.StatusCode, http.StatusOK)
	}

	getReq2, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/apps/%d", srv.URL, appID), nil)
	getReq2.Header.Set("Authorization", "Bearer "+token)
	getResp2, err := http.DefaultClient.Do(getReq2)
	if err != nil {
		t.Fatalf("get-after-delete request: %v", err)
	}
	defer getResp2.Body.Close()
	if getResp2.StatusCode != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want %d", getResp2.StatusCode, http.StatusNotFound)
	}
}

func TestAppList_RequiresAuth(t *testing.T) {
	srv, _, _, cleanup := setupFullRouter(t)
	defer cleanup()

	resp, err := http.Get(srv.URL + "/api/v1/apps")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAppWriteRoutes_RequireAdminOrDeveloperRole(t *testing.T) {
	srv, _, auditorToken, cleanup := setupFullRouter(t)
	defer cleanup()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("tag", "tool"); err != nil {
		t.Fatalf("WriteField(tag): %v", err)
	}
	if err := w.WriteField("packageName", "com.handlertest.rbac"); err != nil {
		t.Fatalf("WriteField(packageName): %v", err)
	}
	if err := w.WriteField("version", "1.0.0"); err != nil {
		t.Fatalf("WriteField(version): %v", err)
	}
	part, err := w.CreateFormFile("file", "rbac.aab")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write([]byte("rbac test content")); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	uploadReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/apps/upload", &buf)
	uploadReq.Header.Set("Content-Type", w.FormDataContentType())
	uploadReq.Header.Set("Authorization", "Bearer "+auditorToken)
	uploadResp, err := http.DefaultClient.Do(uploadReq)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer uploadResp.Body.Close()
	if uploadResp.StatusCode != http.StatusForbidden {
		t.Fatalf("upload status = %d, want %d", uploadResp.StatusCode, http.StatusForbidden)
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/apps", nil)
	listReq.Header.Set("Authorization", "Bearer "+auditorToken)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d (read routes must stay open to auditor)", listResp.StatusCode, http.StatusOK)
	}
}
