package service_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
	"gorm.io/gorm"
)

type fakeHardeningURLStorage struct {
	urls map[string]string
}

type hardeningServiceTestScope struct {
	runID string
}

func (f fakeHardeningURLStorage) PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error) {
	if f.urls == nil {
		return "https://minio.example/" + objectKey, nil
	}
	return f.urls[objectKey], nil
}

func newHardeningServiceTestScope() hardeningServiceTestScope {
	return hardeningServiceTestScope{
		runID: fmt.Sprintf("svc-%d", time.Now().UnixNano()),
	}
}

func (s hardeningServiceTestScope) packageNamePrefix() string {
	return "com.hardening.service." + s.runID
}

func (s hardeningServiceTestScope) packageName(suffix string) string {
	return s.packageNamePrefix() + "." + suffix
}

func (s hardeningServiceTestScope) objectKey(suffix string) string {
	return "service/" + s.runID + "/" + suffix + "/app.apk"
}

func cleanupHardeningServiceTestData(t *testing.T, database *gorm.DB, scope hardeningServiceTestScope) {
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
	database.Unscoped().Where("updated_by = ?", uint(515151)).Delete(&model.Strategy{})
}

func setupHardeningServiceTest(t *testing.T) (*service.HardeningService, *repository.AppRepository, *repository.HardeningRepository, hardeningServiceTestScope) {
	t.Helper()
	scope := newHardeningServiceTestScope()

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

	cleanupHardeningServiceTestData(t, database, scope)

	t.Cleanup(func() {
		cleanupHardeningServiceTestData(t, database, scope)
	})

	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)
	strategyRepo := repository.NewStrategyRepository(database)
	strategySvc := service.NewStrategyService(strategyRepo, nil)
	svc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		nil,
	)
	return svc, appRepo, hardeningRepo, scope
}

func createHardeningServiceApp(t *testing.T, appRepo *repository.AppRepository, scope hardeningServiceTestScope, suffix string) model.App {
	t.Helper()

	app := model.App{
		Name:        "Service App " + suffix,
		PackageName: scope.packageName(suffix),
		Version:     "1.0.0",
		Tag:         model.AppTagTool,
		Status:      model.AppStatusUnprotected,
		ObjectKey:   scope.objectKey(suffix),
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		UploadedBy:  1,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("create app: %v", err)
	}
	return app
}

func TestHardeningService_CreateDefaultsAndSetsAppProcessing(t *testing.T) {
	svc, appRepo, _, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "create")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{
		AppID:     app.ID,
		CreatedBy: 42,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if detail.Task.Status != model.HardeningTaskStatusQueued {
		t.Fatalf("status = %s", detail.Task.Status)
	}
	if detail.Task.StrategyName != service.DefaultStrategyName {
		t.Fatalf("strategy name = %q", detail.Task.StrategyName)
	}
	if !strings.Contains(detail.Task.VMPRulesText, "**") {
		t.Fatalf("rules text = %q", detail.Task.VMPRulesText)
	}
	if len(detail.Steps) != 6 {
		t.Fatalf("len(steps) = %d, want 6", len(detail.Steps))
	}

	found, err := appRepo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.AppStatusProcessing {
		t.Fatalf("app status = %s, want processing", found.Status)
	}
}

func TestHardeningService_CreateRejectsActiveTask(t *testing.T) {
	svc, appRepo, _, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "active")

	_, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 42})
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}

	_, err = svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 42})
	if err != service.ErrHardeningActiveTaskExists {
		t.Fatalf("second err = %v, want ErrHardeningActiveTaskExists", err)
	}
}

func TestHardeningService_CreateUsesCustomSnapshotAndRules(t *testing.T) {
	svc, appRepo, _, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "custom")
	strategy := model.Strategy{DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, RootDetect: true}

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{
		AppID:                    app.ID,
		StrategyName:             "信息院 App 加固模板",
		StrategySnapshot:         &strategy,
		VMPRulesText:             "com.example.**",
		EnableFileIntegrityCheck: true,
		EnableProxyDetect:        true,
		CreatedBy:                7,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if detail.Task.StrategyName != "信息院 App 加固模板" {
		t.Fatalf("strategy name = %q", detail.Task.StrategyName)
	}
	if detail.Task.StrategySnapshot.DexLevel != model.DexLevelLow || !detail.Task.StrategySnapshot.RootDetect {
		t.Fatalf("strategy snapshot = %+v", detail.Task.StrategySnapshot)
	}
	if detail.Task.VMPRulesText != "com.example.**" {
		t.Fatalf("rules = %q", detail.Task.VMPRulesText)
	}
	if !detail.Task.EnableFileIntegrityCheck || !detail.Task.EnableProxyDetect {
		t.Fatalf("advanced flags not preserved: %+v", detail.Task)
	}
}

func TestHardeningService_GetLogsAndHistory(t *testing.T) {
	svc, appRepo, repo, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "read")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 99})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	step, err := repo.FindStep(detail.Task.ID, model.HardeningStepPrepareInput)
	if err != nil {
		t.Fatalf("FindStep() error = %v", err)
	}
	if err := repo.AppendLog(&model.HardeningLog{
		TaskID:  detail.Task.ID,
		StepID:  &step.ID,
		Level:   model.HardeningLogLevelInfo,
		Message: "prepare ok",
	}); err != nil {
		t.Fatalf("AppendLog() error = %v", err)
	}

	found, err := svc.Get(detail.Task.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if found.Task.ID != detail.Task.ID {
		t.Fatalf("Get() task id = %d, want %d", found.Task.ID, detail.Task.ID)
	}
	if len(found.Steps) != 6 {
		t.Fatalf("Get() len(steps) = %d, want 6", len(found.Steps))
	}
	if len(found.RecentLogs) != 1 || found.RecentLogs[0].Message != "prepare ok" {
		t.Fatalf("Get() recent logs = %+v", found.RecentLogs)
	}

	logs, err := svc.Logs(detail.Task.ID, repository.HardeningLogFilter{
		StepKey: model.HardeningStepPrepareInput,
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("Logs() error = %v", err)
	}
	if len(logs) != 1 || logs[0].Message != "prepare ok" {
		t.Fatalf("Logs() = %+v", logs)
	}

	history, err := svc.History(app.ID)
	if err != nil {
		t.Fatalf("History() error = %v", err)
	}
	if len(history) != 1 || history[0].ID != detail.Task.ID {
		t.Fatalf("History() = %+v", history)
	}
}

func TestHardeningService_DownloadURLArtifacts(t *testing.T) {
	svc, appRepo, repo, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "download")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	now := time.Now()
	if err := repo.MarkTaskRunning(detail.Task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := repo.CompleteTaskForApp(detail.Task.ID, "hardening/unsigned.apk", 10, "abc", "hardening/signed.apk", 11, "def", now); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	unsignedURL, err := svc.DownloadURL(context.Background(), detail.Task.ID, "", 0, "")
	if err != nil {
		t.Fatalf("DownloadURL(unsigned) error = %v", err)
	}
	if !strings.Contains(unsignedURL, "hardening/unsigned.apk") {
		t.Fatalf("unsigned URL = %q", unsignedURL)
	}

	signedURL, err := svc.DownloadURL(context.Background(), detail.Task.ID, "signed_test", 0, "")
	if err != nil {
		t.Fatalf("DownloadURL(signed_test) error = %v", err)
	}
	if !strings.Contains(signedURL, "hardening/signed.apk") {
		t.Fatalf("signed URL = %q", signedURL)
	}
}

func TestHardeningService_DownloadURLErrors(t *testing.T) {
	svc, appRepo, _, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "download-errors")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if _, err := svc.DownloadURL(context.Background(), detail.Task.ID, "bad", 0, ""); err != service.ErrInvalidHardeningArtifact {
		t.Fatalf("DownloadURL() invalid artifact err = %v, want ErrInvalidHardeningArtifact", err)
	}
	if _, err := svc.DownloadURL(context.Background(), detail.Task.ID, "", 0, ""); err != service.ErrHardeningArtifactNotFound {
		t.Fatalf("DownloadURL() missing unsigned artifact err = %v, want ErrHardeningArtifactNotFound", err)
	}
	if _, err := svc.DownloadURL(context.Background(), detail.Task.ID, "signed_test", 0, ""); err != service.ErrHardeningArtifactNotFound {
		t.Fatalf("DownloadURL() missing signed artifact err = %v, want ErrHardeningArtifactNotFound", err)
	}
}

func TestHardeningService_ErrorMappings(t *testing.T) {
	svc, _, _, _ := setupHardeningServiceTest(t)

	if _, err := svc.Get(999999); err != service.ErrHardeningTaskNotFound {
		t.Fatalf("Get() err = %v, want ErrHardeningTaskNotFound", err)
	}
	if _, err := svc.Logs(999999, repository.HardeningLogFilter{Limit: 10}); err != service.ErrHardeningTaskNotFound {
		t.Fatalf("Logs() err = %v, want ErrHardeningTaskNotFound", err)
	}
	if _, err := svc.History(999999); err != service.ErrHardeningAppNotFound {
		t.Fatalf("History() err = %v, want ErrHardeningAppNotFound", err)
	}
	if _, err := svc.DownloadURL(context.Background(), 999999, "", 0, ""); err != service.ErrHardeningTaskNotFound {
		t.Fatalf("DownloadURL() missing task err = %v, want ErrHardeningTaskNotFound", err)
	}
	if _, err := svc.DownloadURL(context.Background(), 999999, "bad", 0, ""); err != service.ErrHardeningTaskNotFound {
		t.Fatalf("DownloadURL() missing task with bad artifact err = %v, want ErrHardeningTaskNotFound", err)
	}
}

func TestHardeningService_CreateRejectsConcurrentActiveTask(t *testing.T) {
	svc, appRepo, repo, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "concurrent")
	input := service.CreateHardeningTaskInput{
		AppID:            app.ID,
		CreatedBy:        42,
		StrategyName:     "concurrent",
		StrategySnapshot: &model.Strategy{DexLevel: model.DexLevelLow, SoShell: model.SoShellNone},
		VMPRulesText:     "concurrent.**",
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup

	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.Create(context.Background(), input)
			errs <- err
		}()
	}

	close(start)
	wg.Wait()
	close(errs)

	var successCount int
	var activeErrCount int
	for err := range errs {
		switch err {
		case nil:
			successCount++
		case service.ErrHardeningActiveTaskExists:
			activeErrCount++
		default:
			t.Fatalf("Create() concurrent err = %v", err)
		}
	}
	if successCount != 1 || activeErrCount != 1 {
		t.Fatalf("success=%d activeErr=%d, want 1/1", successCount, activeErrCount)
	}

	history, err := repo.RecentByApp(app.ID, 10)
	if err != nil {
		t.Fatalf("RecentByApp() error = %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("len(history) = %d, want 1", len(history))
	}

	found, err := appRepo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.AppStatusProcessing {
		t.Fatalf("app status = %s, want processing", found.Status)
	}
}
