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
		ObjectKey: "com.migrationtest.app/abc/app.apk",
		MD5:       "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
		UploadedBy: 1,
	}
	database.Unscoped().Where("package_name = ?", testApp.PackageName).Delete(&model.App{})

	if err := database.Create(&testApp).Error; err != nil {
		t.Fatalf("failed to insert into apps table: %v", err)
	}

	database.Unscoped().Where("package_name = ?", testApp.PackageName).Delete(&model.App{})
}
