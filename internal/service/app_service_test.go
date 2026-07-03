package service_test

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"os"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func buildFileHeader(t *testing.T, fieldName, fileName string, content []byte) *multipart.FileHeader {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	r := multipart.NewReader(&buf, w.Boundary())
	form, err := r.ReadForm(int64(len(content)) + 1024)
	if err != nil {
		t.Fatalf("ReadForm() error = %v", err)
	}
	t.Cleanup(func() { form.RemoveAll() })

	return form.File[fieldName][0]
}

func setupAppService(t *testing.T) *service.AppService {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)

	st, err := storage.NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := st.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v (is `make dev-up` running?)", err)
	}

	return service.NewAppService(appRepo, hardeningRepo, st, 10, nil)
}

func setupAppServiceWithAudit(t *testing.T) (*service.AppService, *service.AuditService, string, uint) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	marker := fmt.Sprintf("app-audit-%d", time.Now().UnixNano())
	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 400_000)
	t.Cleanup(func() {
		database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
		database.Unscoped().Where("package_name LIKE ?", "com.svcaudittest.%").Delete(&model.App{})
	})
	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)
	auditService := service.NewAuditService(repository.NewAuditRepository(database))

	st, err := storage.NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := st.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v (is MinIO running?)", err)
	}

	return service.NewAppService(appRepo, hardeningRepo, st, 10, auditService), auditService, marker, actorID
}

func TestAppService_Upload_ManualPackageInfo(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "notreal.aab", []byte("not a real aab, just bytes for testing"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svctest.aabapp",
		ManualVersion:     "2.0.0",
		UploadedBy:        1,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID, 0, "") })

	if app.PackageName != "com.svctest.aabapp" {
		t.Errorf("PackageName = %q, want %q", app.PackageName, "com.svctest.aabapp")
	}
	if app.Status != model.AppStatusUnprotected {
		t.Errorf("Status = %q, want %q", app.Status, model.AppStatusUnprotected)
	}
	if app.MD5 == "" || app.SHA256 == "" {
		t.Error("expected non-empty MD5/SHA256")
	}

	fetched, err := svc.Get(app.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if fetched.ID != app.ID {
		t.Errorf("Get() returned different app")
	}

	downloadURL, err := svc.DownloadURL(ctx, app.ID, 0, "")
	if err != nil {
		t.Fatalf("DownloadURL() error = %v", err)
	}
	if downloadURL == "" {
		t.Error("expected non-empty download URL")
	}
}

func TestAppService_Upload_AutoParsesAPKPackageInfo(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	content, err := os.ReadFile("../pkg/manifest/testdata/helloworld.apk")
	if err != nil {
		t.Fatalf("read fixture apk: %v", err)
	}
	fh := buildFileHeader(t, "file", "helloworld.apk", content)

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID, 0, "") })

	if app.PackageName != "com.example.helloworld" {
		t.Errorf("PackageName = %q, want %q (auto-parsed)", app.PackageName, "com.example.helloworld")
	}
}

func TestAppService_Upload_MissingPackageInfoForAAB(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "noinfo.aab", []byte("bytes without package info"))

	_, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != service.ErrMissingPackageInfo {
		t.Errorf("err = %v, want %v", err, service.ErrMissingPackageInfo)
	}
}

func TestAppService_Upload_RejectsUnsupportedExtension(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "app.exe", []byte("nope"))

	_, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != service.ErrUnsupportedFileType {
		t.Errorf("err = %v, want %v", err, service.ErrUnsupportedFileType)
	}
}

func TestAppService_UploadRecordsAuditEntry(t *testing.T) {
	svc, auditService, marker, actorID := setupAppServiceWithAudit(t)
	ctx := context.Background()
	fh := buildFileHeader(t, "file", "audit-upload.aab", []byte("audit upload bytes"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svcaudittest.upload",
		ManualVersion:     "1.0.0",
		UploadedBy:        actorID,
		IP:                marker,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID, actorID, marker) })

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionAppUpload),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].TargetID != app.ID || logs[0].TargetType != "app" || !logs[0].Success {
		t.Fatalf("unexpected app upload audit rows len=%d total=%d rows=%+v", len(logs), total, logs)
	}
}

func TestAppService_DeleteRecordsAuditEntry(t *testing.T) {
	svc, auditService, marker, actorID := setupAppServiceWithAudit(t)
	ctx := context.Background()
	fh := buildFileHeader(t, "file", "audit-delete.aab", []byte("audit delete bytes"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svcaudittest.delete",
		ManualVersion:     "1.0.0",
		UploadedBy:        actorID,
		IP:                marker,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	if err := svc.Delete(ctx, app.ID, actorID, marker); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionAppDelete),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].TargetID != app.ID || logs[0].TargetType != "app" || !logs[0].Success {
		t.Fatalf("unexpected app delete audit rows len=%d total=%d rows=%+v", len(logs), total, logs)
	}
}

// findAppAuditLogsForTarget queries audit_logs for a given action/targetType
// (AuditListFilter has no TargetID field) and filters by TargetID client-side,
// mirroring handler_test's findAuditLogForTarget helper (unavailable here
// since app_service_test.go lives in package service_test, not handler_test).
func findAppAuditLogsForTarget(t *testing.T, auditService *service.AuditService, action, targetType string, targetID uint) []model.AuditLog {
	t.Helper()
	logs, _, err := auditService.List(repository.AuditListFilter{
		Action:     action,
		TargetType: targetType,
		Page:       1,
		PageSize:   100,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}
	var matches []model.AuditLog
	for _, l := range logs {
		if l.TargetID == targetID {
			matches = append(matches, l)
		}
	}
	return matches
}

func TestAppService_Upload_UnsupportedExtensionRecordsFailureAuditEntry(t *testing.T) {
	svc, auditService, marker, actorID := setupAppServiceWithAudit(t)
	ctx := context.Background()
	fh := buildFileHeader(t, "file", "audit-bad-ext.exe", []byte("nope"))

	_, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: actorID,
		IP:         marker,
	})
	if err != service.ErrUnsupportedFileType {
		t.Fatalf("err = %v, want %v", err, service.ErrUnsupportedFileType)
	}

	matches := findAppAuditLogsForTarget(t, auditService, string(model.AuditActionAppUpload), "app", 0)
	if len(matches) != 1 {
		t.Fatalf("app.upload audit rows for TargetID=0 = %+v, want exactly one", matches)
	}
	if matches[0].Success {
		t.Fatalf("expected Success = false, got row %+v", matches[0])
	}
}

func TestAppService_Upload_SuccessRecordsExactlyOneAuditEntry(t *testing.T) {
	svc, auditService, marker, actorID := setupAppServiceWithAudit(t)
	ctx := context.Background()
	fh := buildFileHeader(t, "file", "audit-single-record.aab", []byte("single record bytes"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svcaudittest.singlerecord",
		ManualVersion:     "1.0.0",
		UploadedBy:        actorID,
		IP:                marker,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID, actorID, marker) })

	matches := findAppAuditLogsForTarget(t, auditService, string(model.AuditActionAppUpload), "app", app.ID)
	if len(matches) != 1 {
		t.Fatalf("app.upload audit rows for TargetID=%d = %+v, want exactly one (no double-recording)", app.ID, matches)
	}
	if !matches[0].Success {
		t.Fatalf("expected Success = true, got row %+v", matches[0])
	}
}

func TestAppService_Delete_NonexistentAppRecordsFailureAuditEntry(t *testing.T) {
	svc, auditService, marker, actorID := setupAppServiceWithAudit(t)
	ctx := context.Background()

	nonexistentID := uint(time.Now().UnixNano()%1_000_000_000 + 900_000_000)

	err := svc.Delete(ctx, nonexistentID, actorID, marker)
	if err != service.ErrAppNotFound {
		t.Fatalf("err = %v, want %v", err, service.ErrAppNotFound)
	}

	matches := findAppAuditLogsForTarget(t, auditService, string(model.AuditActionAppDelete), "app", nonexistentID)
	if len(matches) != 1 {
		t.Fatalf("app.delete audit rows for TargetID=%d = %+v, want exactly one", nonexistentID, matches)
	}
	if matches[0].Success {
		t.Fatalf("expected Success = false, got row %+v", matches[0])
	}
}

func TestAppService_Delete_ActiveHardeningTaskRecordsFailureAuditEntry(t *testing.T) {
	svc, auditService, marker, actorID := setupAppServiceWithAudit(t)
	ctx := context.Background()
	fh := buildFileHeader(t, "file", "audit-active-task.aab", []byte("active task bytes"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svcaudittest.activetask",
		ManualVersion:     "1.0.0",
		UploadedBy:        actorID,
		IP:                marker,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}

	database, err := db.Connect(&config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	hardeningRepo := repository.NewHardeningRepository(database)
	task := &model.HardeningTask{
		TaskNo:           fmt.Sprintf("svc-appdel-%d", time.Now().UnixNano()),
		AppID:            app.ID,
		Status:           model.HardeningTaskStatusQueued,
		StrategyName:     "默认加固模板",
		StrategySnapshot: model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP},
		CreatedBy:        actorID,
	}
	if err := hardeningRepo.CreateTaskWithStepsForApp(task, model.AppStatusProcessing); err != nil {
		t.Fatalf("CreateTaskWithStepsForApp() error = %v", err)
	}
	t.Cleanup(func() {
		database.Exec(`DELETE FROM hardening_steps WHERE task_id = ?`, task.ID)
		database.Exec(`DELETE FROM hardening_tasks WHERE id = ?`, task.ID)
		_ = svc.Delete(ctx, app.ID, actorID, marker)
	})

	err = svc.Delete(ctx, app.ID, actorID, marker)
	if err != service.ErrAppHasActiveHardeningTask {
		t.Fatalf("err = %v, want %v", err, service.ErrAppHasActiveHardeningTask)
	}

	matches := findAppAuditLogsForTarget(t, auditService, string(model.AuditActionAppDelete), "app", app.ID)
	if len(matches) != 1 {
		t.Fatalf("app.delete audit rows for TargetID=%d = %+v, want exactly one", app.ID, matches)
	}
	if matches[0].Success {
		t.Fatalf("expected Success = false, got row %+v", matches[0])
	}
}

func TestAppService_DownloadURLRecordsAuditEntry(t *testing.T) {
	svc, auditService, marker, actorID := setupAppServiceWithAudit(t)
	ctx := context.Background()
	fh := buildFileHeader(t, "file", "audit-download.aab", []byte("audit download bytes"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svcaudittest.download",
		ManualVersion:     "1.0.0",
		UploadedBy:        actorID,
		IP:                marker,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID, actorID, marker) })

	downloadURL, err := svc.DownloadURL(ctx, app.ID, actorID, marker)
	if err != nil {
		t.Fatalf("DownloadURL() error = %v", err)
	}
	if downloadURL == "" {
		t.Fatal("expected non-empty download URL")
	}

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionAppDownload),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].TargetID != app.ID || logs[0].TargetType != "app" || !logs[0].Success {
		t.Fatalf("unexpected app download audit rows len=%d total=%d rows=%+v", len(logs), total, logs)
	}
}
