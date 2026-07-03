package repository

import (
	"errors"
	"testing"

	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
)

func setupAppRepo(t *testing.T) *AppRepository {
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
	database.Unscoped().Where("package_name LIKE ?", "com.repotest.%").Delete(&model.App{})
	t.Cleanup(func() {
		database.Unscoped().Where("package_name LIKE ?", "com.repotest.%").Delete(&model.App{})
	})
	return NewAppRepository(database)
}

func TestAppRepository_CreateFindDelete(t *testing.T) {
	repo := setupAppRepo(t)

	app := model.App{
		Name: "测试应用", PackageName: "com.repotest.one", Version: "1.0.0",
		Tag: model.AppTagTool, Status: model.AppStatusUnprotected,
		FileSize: 1024, ObjectKey: "com.repotest.one/abc/app.apk",
		MD5:        "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
		UploadedBy: 1,
	}
	if err := repo.Create(&app); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if app.ID == 0 {
		t.Fatal("expected ID to be set after Create()")
	}

	found, err := repo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.PackageName != app.PackageName {
		t.Errorf("PackageName = %q, want %q", found.PackageName, app.PackageName)
	}

	if err := repo.Delete(app.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repo.FindByID(app.ID); err == nil {
		t.Fatal("expected error finding deleted app, got nil")
	}
}

func TestAppRepository_ListFilters(t *testing.T) {
	repo := setupAppRepo(t)

	apps := []model.App{
		{Name: "金融应用", PackageName: "com.repotest.finance", Version: "1.0",
			Tag: model.AppTagFinance, Status: model.AppStatusCompleted,
			ObjectKey: "k1", MD5: "m1", SHA256: "s1", UploadedBy: 1},
		{Name: "游戏应用", PackageName: "com.repotest.game", Version: "1.0",
			Tag: model.AppTagGame, Status: model.AppStatusUnprotected,
			ObjectKey: "k2", MD5: "m2", SHA256: "s2", UploadedBy: 1},
	}
	for i := range apps {
		if err := repo.Create(&apps[i]); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	result, total, err := repo.List(AppListFilter{Tag: "finance", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(result) != 1 || result[0].PackageName != "com.repotest.finance" {
		t.Errorf("unexpected result: %+v", result)
	}

	result, total, err = repo.List(AppListFilter{Search: "游戏", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 || result[0].PackageName != "com.repotest.game" {
		t.Errorf("unexpected search result: %+v total=%d", result, total)
	}
}

func TestAppRepository_UpdateStatus(t *testing.T) {
	repo := setupAppRepo(t)

	app := model.App{
		Name:        "状态测试应用",
		PackageName: "com.repotest.status",
		Version:     "1.0.0",
		Tag:         model.AppTagTool,
		Status:      model.AppStatusUnprotected,
		ObjectKey:   "status/app.apk",
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		UploadedBy:  1,
	}
	if err := repo.Create(&app); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := repo.UpdateStatus(app.ID, model.AppStatusProcessing); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}

	found, err := repo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.AppStatusProcessing {
		t.Fatalf("Status = %q, want %q", found.Status, model.AppStatusProcessing)
	}

	if err := repo.UpdateStatus(app.ID+9999, model.AppStatusFailed); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("UpdateStatus() missing app error = %v, want %v", err, gorm.ErrRecordNotFound)
	}
}

func TestAppRepository_TopByRiskLevelOrdersBySeverity(t *testing.T) {
	repo := setupAppRepo(t)

	low := model.RiskLevelLow
	medium := model.RiskLevelMedium
	critical := model.RiskLevelCritical

	apps := []model.App{
		{Name: "低风险应用", PackageName: "com.repotest.risk.low", Version: "1.0",
			Tag: model.AppTagTool, Status: model.AppStatusCompleted, RiskLevel: &low,
			ObjectKey: "k-low", MD5: "m1", SHA256: "s1", UploadedBy: 1},
		{Name: "中风险应用", PackageName: "com.repotest.risk.medium", Version: "1.0",
			Tag: model.AppTagTool, Status: model.AppStatusCompleted, RiskLevel: &medium,
			ObjectKey: "k-medium", MD5: "m2", SHA256: "s2", UploadedBy: 1},
		{Name: "严重风险应用", PackageName: "com.repotest.risk.critical", Version: "1.0",
			Tag: model.AppTagTool, Status: model.AppStatusCompleted, RiskLevel: &critical,
			ObjectKey: "k-critical", MD5: "m3", SHA256: "s3", UploadedBy: 1},
	}
	for i := range apps {
		if err := repo.Create(&apps[i]); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	result, err := repo.TopByRiskLevel(20)
	if err != nil {
		t.Fatalf("TopByRiskLevel() error = %v", err)
	}

	positions := map[string]int{}
	for i, app := range result {
		switch app.PackageName {
		case "com.repotest.risk.low", "com.repotest.risk.medium", "com.repotest.risk.critical":
			positions[app.PackageName] = i
		}
	}
	if len(positions) != 3 {
		t.Fatalf("expected all 3 test apps in result, found positions: %+v (result len=%d)", positions, len(result))
	}
	if positions["com.repotest.risk.critical"] >= positions["com.repotest.risk.medium"] {
		t.Fatalf("critical (pos %d) should rank above medium (pos %d)", positions["com.repotest.risk.critical"], positions["com.repotest.risk.medium"])
	}
	if positions["com.repotest.risk.medium"] >= positions["com.repotest.risk.low"] {
		t.Fatalf("medium (pos %d) should rank above low (pos %d)", positions["com.repotest.risk.medium"], positions["com.repotest.risk.low"])
	}
}
