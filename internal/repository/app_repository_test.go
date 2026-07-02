package repository

import (
	"testing"

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
}
