package service_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func setupAuditRetrofitDB(t *testing.T, markerPrefix string) (*gorm.DB, *service.AuditService, string, uint) {
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
	marker := fmt.Sprintf("%s-%d", markerPrefix, time.Now().UnixNano())
	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 500_000)
	t.Cleanup(func() {
		database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
	})
	return database, service.NewAuditService(repository.NewAuditRepository(database)), marker, actorID
}

func findAuditLogs(t *testing.T, auditService *service.AuditService, actorID uint, action model.AuditAction) []model.AuditLog {
	t.Helper()
	logs, _, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(action),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}
	return logs
}

func TestStrategyService_SaveRecordsAuditAndValidationFailureDoesNot(t *testing.T) {
	database, auditService, marker, actorID := setupAuditRetrofitDB(t, "strategy-audit")
	database.Unscoped().Where("1 = 1").Delete(&model.Strategy{})
	t.Cleanup(func() { database.Unscoped().Where("1 = 1").Delete(&model.Strategy{}) })

	svc := service.NewStrategyService(repository.NewStrategyRepository(database), auditService)
	saved, err := svc.Save(service.SaveStrategyInput{
		DexLevel: model.DexLevelMedium, SoShell: model.SoShellAES, SoStrength: 70,
	}, actorID, marker)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	logs := findAuditLogs(t, auditService, actorID, model.AuditActionStrategySave)
	if len(logs) != 1 || logs[0].TargetType != "strategy" || logs[0].TargetID != saved.ID || logs[0].Detail != "全局加固策略已更新" {
		t.Fatalf("unexpected strategy audit logs: %+v", logs)
	}

	_, err = svc.Save(service.SaveStrategyInput{
		DexLevel: "bad-level", SoShell: model.SoShellAES, SoStrength: 70,
	}, actorID, marker)
	if err != service.ErrInvalidDexLevel {
		t.Fatalf("Save() validation error = %v, want %v", err, service.ErrInvalidDexLevel)
	}
	logs = findAuditLogs(t, auditService, actorID, model.AuditActionStrategySave)
	if len(logs) != 1 {
		t.Fatalf("validation failure should not create audit row, got %+v", logs)
	}
}

func TestUserService_CreateUpdateStatusRecordsAudit(t *testing.T) {
	database, auditService, marker, actorID := setupAuditRetrofitDB(t, "user-audit")
	userRepo := repository.NewUserRepository(database)
	svc := service.NewUserService(userRepo, auditService)
	email := fmt.Sprintf("user-audit-%d@beetleshield.com", time.Now().UnixNano())
	t.Cleanup(func() { userRepo.DeleteByEmail(email) })

	user, err := svc.Create(service.CreateUserInput{
		Name: "审计用户", Email: email, Password: "Password123!",
		Role: model.RoleDeveloper, ActorUserID: actorID, IP: marker,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	createLogs := findAuditLogs(t, auditService, actorID, model.AuditActionUserCreate)
	if len(createLogs) != 1 || createLogs[0].TargetID != user.ID || createLogs[0].Detail != email+" (developer)" {
		t.Fatalf("unexpected user create audit logs: %+v", createLogs)
	}

	_, err = svc.Create(service.CreateUserInput{
		Name: "重复用户", Email: email, Password: "Password123!",
		Role: model.RoleDeveloper, ActorUserID: actorID, IP: marker,
	})
	if err != service.ErrEmailAlreadyExists {
		t.Fatalf("duplicate Create() error = %v, want %v", err, service.ErrEmailAlreadyExists)
	}
	createLogs = findAuditLogs(t, auditService, actorID, model.AuditActionUserCreate)
	if len(createLogs) != 1 {
		t.Fatalf("duplicate create should not create audit row, got %+v", createLogs)
	}

	newName := "审计用户已编辑"
	if _, err := svc.Update(user.ID, service.UpdateUserInput{Name: &newName}, actorID, marker); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	updateLogs := findAuditLogs(t, auditService, actorID, model.AuditActionUserUpdate)
	if len(updateLogs) != 1 || updateLogs[0].TargetID != user.ID || updateLogs[0].Detail != "用户资料已更新" {
		t.Fatalf("unexpected user update audit logs: %+v", updateLogs)
	}

	if err := svc.UpdateStatus(user.ID, model.UserStatusDisabled, actorID, marker); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	statusLogs := findAuditLogs(t, auditService, actorID, model.AuditActionUserStatusChange)
	if len(statusLogs) != 1 || statusLogs[0].TargetID != user.ID || statusLogs[0].Detail != "状态变更为 禁用" {
		t.Fatalf("unexpected user status audit logs: %+v", statusLogs)
	}
}

func TestHardeningService_CreateRecordsAuditEntry(t *testing.T) {
	database, auditService, marker, actorID := setupAuditRetrofitDB(t, "hardening-audit")
	scope := newHardeningServiceTestScope()
	cleanupHardeningServiceTestData(t, database, scope)
	t.Cleanup(func() { cleanupHardeningServiceTestData(t, database, scope) })

	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)
	strategySvc := service.NewStrategyService(repository.NewStrategyRepository(database), nil)
	svc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		auditService,
	)
	app := createHardeningServiceApp(t, appRepo, scope, "audit")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{
		AppID:     app.ID,
		CreatedBy: actorID,
		IP:        marker,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	logs := findAuditLogs(t, auditService, actorID, model.AuditActionHardeningCreate)
	if len(logs) != 1 || logs[0].TargetType != "hardening_task" || logs[0].TargetID != detail.Task.ID || logs[0].Detail != app.Name+" / "+detail.Task.TaskNo {
		t.Fatalf("unexpected hardening audit logs: %+v", logs)
	}
}

func TestHardeningService_DownloadURLRecordsAuditEntry(t *testing.T) {
	database, auditService, marker, actorID := setupAuditRetrofitDB(t, "hardening-download-audit")
	scope := newHardeningServiceTestScope()
	cleanupHardeningServiceTestData(t, database, scope)
	t.Cleanup(func() { cleanupHardeningServiceTestData(t, database, scope) })

	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)
	strategySvc := service.NewStrategyService(repository.NewStrategyRepository(database), nil)
	svc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		auditService,
	)
	app := createHardeningServiceApp(t, appRepo, scope, "download-audit")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{
		AppID:     app.ID,
		CreatedBy: actorID,
		IP:        marker,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	now := time.Now()
	if err := hardeningRepo.MarkTaskRunning(detail.Task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := hardeningRepo.CompleteTaskForApp(detail.Task.ID, "hardening/unsigned-download.apk", 10, "abc", "", 0, "", now); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	downloadURL, err := svc.DownloadURL(context.Background(), detail.Task.ID, "unsigned", actorID, marker)
	if err != nil {
		t.Fatalf("DownloadURL() error = %v", err)
	}
	if downloadURL == "" {
		t.Fatal("expected non-empty download URL")
	}

	logs := findAuditLogs(t, auditService, actorID, model.AuditActionHardeningDownload)
	if len(logs) != 1 || logs[0].TargetType != "hardening_task" || logs[0].TargetID != detail.Task.ID || logs[0].Detail != app.Name+" / "+detail.Task.TaskNo+" / unsigned" {
		t.Fatalf("unexpected hardening download audit logs: %+v", logs)
	}
}
