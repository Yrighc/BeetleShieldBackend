package repository

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
)

func setupStrategyRepo(t *testing.T) *StrategyRepository {
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
	database.Unscoped().Where("1 = 1").Delete(&model.Strategy{})
	t.Cleanup(func() {
		database.Unscoped().Where("1 = 1").Delete(&model.Strategy{})
	})
	return NewStrategyRepository(database)
}

func TestStrategyRepository_GetCurrent_NotFound(t *testing.T) {
	repo := setupStrategyRepo(t)

	_, err := repo.GetCurrent()
	if err == nil {
		t.Fatal("expected error when no strategy has been saved, got nil")
	}
}

func TestStrategyRepository_SaveAndGetCurrent(t *testing.T) {
	repo := setupStrategyRepo(t)

	strategy := &model.Strategy{
		Name: "默认加固策略", IsDefault: true,
		Frida: true, DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP,
		SoStrength: 90, TargetSos: []string{"libnative-lib.so", "libsec.so"},
		RootDetect: true, UpdatedBy: 1,
	}
	if err := repo.SaveCurrent(strategy); err != nil {
		t.Fatalf("SaveCurrent() error = %v", err)
	}

	current, err := repo.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() error = %v", err)
	}
	if !current.IsDefault || current.Name != "默认加固策略" {
		t.Errorf("current metadata = name %q isDefault %v", current.Name, current.IsDefault)
	}
	if current.DexLevel != model.DexLevelHigh || current.SoStrength != 90 {
		t.Errorf("unexpected saved strategy: %+v", current)
	}
	if len(current.TargetSos) != 2 || current.TargetSos[0] != "libnative-lib.so" {
		t.Errorf("TargetSos not persisted correctly: %+v", current.TargetSos)
	}

	strategy2 := &model.Strategy{
		Name: "默认加固策略", IsDefault: true,
		Frida: false, DexLevel: model.DexLevelLow, SoShell: model.SoShellNone,
		SoStrength: 0, TargetSos: []string{}, RootDetect: false, UpdatedBy: 2,
	}
	if err := repo.SaveCurrent(strategy2); err != nil {
		t.Fatalf("second SaveCurrent() error = %v", err)
	}

	updated, err := repo.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() after second save error = %v", err)
	}
	if updated.Frida != false || updated.DexLevel != model.DexLevelLow || updated.SoStrength != 0 {
		t.Errorf("second Save() did not overwrite zero values correctly: %+v", updated)
	}

	var count int64
	repo.db.Model(&model.Strategy{}).Count(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 strategy row after two saves, got %d", count)
	}
}

func TestStrategyRepository_ListOnlyRegularStrategies(t *testing.T) {
	repo := setupStrategyRepo(t)

	if err := repo.SaveCurrent(&model.Strategy{
		Name: "默认加固策略", IsDefault: true,
		DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, SoStrength: 90,
	}); err != nil {
		t.Fatalf("SaveCurrent() error = %v", err)
	}
	regular := &model.Strategy{
		Name: "数信学院加固策略", Description: "高强度配置",
		DexLevel: model.DexLevelMedium, SoShell: model.SoShellVMP, SoStrength: 70,
	}
	if err := repo.Create(regular); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	items, total, err := repo.List(StrategyListFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("List() total=%d len=%d, want one regular strategy", total, len(items))
	}
	if items[0].Name != "数信学院加固策略" || items[0].IsDefault {
		t.Fatalf("List() item = %+v", items[0])
	}

	filtered, filteredTotal, err := repo.List(StrategyListFilter{Search: "数信", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("filtered List() error = %v", err)
	}
	if filteredTotal != 1 || len(filtered) != 1 || filtered[0].ID != regular.ID {
		t.Fatalf("filtered List() = %+v total=%d, want regular strategy", filtered, filteredTotal)
	}
}

func TestStrategyRepository_NameExistsExcludesCurrentID(t *testing.T) {
	repo := setupStrategyRepo(t)

	first := &model.Strategy{Name: "数信学院加固策略", DexLevel: model.DexLevelMedium, SoShell: model.SoShellVMP, SoStrength: 70}
	if err := repo.Create(first); err != nil {
		t.Fatalf("Create(first) error = %v", err)
	}
	second := &model.Strategy{Name: "金融高强度策略", DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, SoStrength: 90}
	if err := repo.Create(second); err != nil {
		t.Fatalf("Create(second) error = %v", err)
	}

	exists, err := repo.NameExists(first.Name, 0)
	if err != nil {
		t.Fatalf("NameExists() error = %v", err)
	}
	if !exists {
		t.Fatal("NameExists() = false, want true")
	}

	exists, err = repo.NameExists(first.Name, first.ID)
	if err != nil {
		t.Fatalf("NameExists(exclude same) error = %v", err)
	}
	if exists {
		t.Fatal("NameExists() with excluded same ID = true, want false")
	}

	exists, err = repo.NameExists(first.Name, second.ID)
	if err != nil {
		t.Fatalf("NameExists(exclude other) error = %v", err)
	}
	if !exists {
		t.Fatal("NameExists() with excluded other ID = false, want true")
	}
}

func TestStrategyRepository_FindRegularAndDelete(t *testing.T) {
	repo := setupStrategyRepo(t)

	if err := repo.SaveCurrent(&model.Strategy{
		Name: "默认加固策略", IsDefault: true,
		DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, SoStrength: 90,
	}); err != nil {
		t.Fatalf("SaveCurrent() error = %v", err)
	}
	current, err := repo.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() error = %v", err)
	}
	if _, err := repo.FindRegularByID(current.ID); err == nil {
		t.Fatal("FindRegularByID(default) error = nil, want not found")
	}

	regular := &model.Strategy{Name: "基础兼容策略", DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, SoStrength: 30}
	if err := repo.Create(regular); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	found, err := repo.FindRegularByID(regular.ID)
	if err != nil {
		t.Fatalf("FindRegularByID(regular) error = %v", err)
	}
	if found.Name != regular.Name {
		t.Fatalf("FindRegularByID() name = %q, want %q", found.Name, regular.Name)
	}

	if err := repo.Delete(regular.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repo.FindByID(regular.ID); err == nil {
		t.Fatal("FindByID(deleted) error = nil, want not found")
	}
}

func TestStrategyRepository_PromoteLegacyCurrent(t *testing.T) {
	repo := setupStrategyRepo(t)

	legacy := &model.Strategy{
		DexLevel: model.DexLevelMedium, SoShell: model.SoShellVMP,
		SoStrength: 70, UpdatedBy: 9,
	}
	if err := repo.db.Create(legacy).Error; err != nil {
		t.Fatalf("create legacy strategy: %v", err)
	}

	promoted, err := repo.PromoteLegacyCurrent()
	if err != nil {
		t.Fatalf("PromoteLegacyCurrent() error = %v", err)
	}
	if promoted.ID != legacy.ID || !promoted.IsDefault || promoted.Name != "默认加固策略" {
		t.Fatalf("promoted = %+v", promoted)
	}
}
