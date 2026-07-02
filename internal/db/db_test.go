package db

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/model"
)

func testConfig() *config.Config {
	return &config.Config{
		DBHost:     "localhost",
		DBPort:     "5432",
		DBUser:     "root",
		DBPassword: "root",
		DBName:     "beetleshield",
		DBSSLMode:  "disable",
	}
}

func TestMigrateAndSeedAdmin(t *testing.T) {
	cfg := testConfig()
	database, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}

	if err := Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	database.Unscoped().Where("email = ?", "seed-test-admin@beetleshield.com").Delete(&model.User{})

	if err := SeedAdmin(database, "seed-test-admin@beetleshield.com", "TestPassword123!"); err != nil {
		t.Fatalf("SeedAdmin() error = %v", err)
	}

	var user model.User
	if err := database.Where("email = ?", "seed-test-admin@beetleshield.com").First(&user).Error; err != nil {
		t.Fatalf("expected seeded admin to exist: %v", err)
	}
	if user.Role != model.RoleAdmin {
		t.Errorf("Role = %q, want %q", user.Role, model.RoleAdmin)
	}

	if err := SeedAdmin(database, "seed-test-admin@beetleshield.com", "TestPassword123!"); err != nil {
		t.Fatalf("second SeedAdmin() error = %v", err)
	}
	var count int64
	database.Model(&model.User{}).Where("email = ?", "seed-test-admin@beetleshield.com").Count(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 user after duplicate seed, got %d", count)
	}

	database.Unscoped().Where("email = ?", "seed-test-admin@beetleshield.com").Delete(&model.User{})
}

func TestMigrate_AppsTable(t *testing.T) {
	cfg := testConfig()
	database, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	testApp := model.App{
		Name: "迁移测试应用", PackageName: "com.migrationtest.app", Version: "0.0.1",
		Tag: model.AppTagTool, Status: model.AppStatusUnprotected,
		ObjectKey:  "com.migrationtest.app/abc/app.apk",
		MD5:        "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
		UploadedBy: 1,
	}
	database.Unscoped().Where("package_name = ?", testApp.PackageName).Delete(&model.App{})

	if err := database.Create(&testApp).Error; err != nil {
		t.Fatalf("failed to insert into apps table: %v", err)
	}

	database.Unscoped().Where("package_name = ?", testApp.PackageName).Delete(&model.App{})
}

func TestMigrate_StrategiesTable(t *testing.T) {
	cfg := testConfig()
	database, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	testStrategy := model.Strategy{
		DexLevel:   model.DexLevelHigh,
		SoShell:    model.SoShellVMP,
		SoStrength: 90,
		TargetSos:  []string{"libnative-lib.so"},
		UpdatedBy:  999999,
	}
	database.Unscoped().Where("updated_by = ?", uint(999999)).Delete(&model.Strategy{})

	if err := database.Create(&testStrategy).Error; err != nil {
		t.Fatalf("failed to insert into strategies table: %v", err)
	}

	var readBack model.Strategy
	if err := database.First(&readBack, testStrategy.ID).Error; err != nil {
		t.Fatalf("failed to read back inserted strategy: %v", err)
	}
	if len(readBack.TargetSos) != 1 || readBack.TargetSos[0] != "libnative-lib.so" {
		t.Errorf("TargetSos not round-tripped correctly via JSON serializer: %+v", readBack.TargetSos)
	}

	database.Unscoped().Where("updated_by = ?", uint(999999)).Delete(&model.Strategy{})
}

func TestMigrate_HardeningTables(t *testing.T) {
	cfg := testConfig()
	database, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	app := model.App{
		Name:        "Hardening Migration Test",
		PackageName: "com.hardening.migration.test",
		Version:     "1.0.0",
		Tag:         model.AppTagTool,
		Status:      model.AppStatusUnprotected,
		ObjectKey:   "hardening/migration/app.apk",
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		UploadedBy:  1,
	}
	database.Unscoped().Where("package_name = ?", app.PackageName).Delete(&model.App{})
	if err := database.Create(&app).Error; err != nil {
		t.Fatalf("create app: %v", err)
	}
	defer database.Unscoped().Where("package_name = ?", app.PackageName).Delete(&model.App{})

	task := model.HardeningTask{
		TaskNo:           "TASK-MIGRATION-001",
		AppID:            app.ID,
		Status:           model.HardeningTaskStatusQueued,
		StrategyName:     "默认加固模板",
		StrategySnapshot: model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP},
		VMPRulesText:     "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		CreatedBy:        1,
	}
	database.Unscoped().Where("task_no = ?", task.TaskNo).Delete(&model.HardeningTask{})
	if err := database.Create(&task).Error; err != nil {
		t.Fatalf("create hardening task: %v", err)
	}
	defer database.Unscoped().Where("task_no = ?", task.TaskNo).Delete(&model.HardeningTask{})

	step := model.HardeningStep{
		TaskID:    task.ID,
		StepKey:   model.HardeningStepPrepareInput,
		Name:      "准备输入",
		Status:    model.HardeningStepStatusWaiting,
		SortOrder: 1,
	}
	if err := database.Create(&step).Error; err != nil {
		t.Fatalf("create hardening step: %v", err)
	}

	logLine := model.HardeningLog{
		TaskID:  task.ID,
		StepID:  &step.ID,
		Level:   model.HardeningLogLevelInfo,
		Message: "migration log line",
	}
	if err := database.Create(&logLine).Error; err != nil {
		t.Fatalf("create hardening log: %v", err)
	}
}
