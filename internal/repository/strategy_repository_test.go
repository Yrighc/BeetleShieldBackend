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
		Frida: true, DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP,
		SoStrength: 90, TargetSos: []string{"libnative-lib.so", "libsec.so"},
		RootDetect: true, UpdatedBy: 1,
	}
	if err := repo.Save(strategy); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	current, err := repo.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() error = %v", err)
	}
	if current.DexLevel != model.DexLevelHigh || current.SoStrength != 90 {
		t.Errorf("unexpected saved strategy: %+v", current)
	}
	if len(current.TargetSos) != 2 || current.TargetSos[0] != "libnative-lib.so" {
		t.Errorf("TargetSos not persisted correctly: %+v", current.TargetSos)
	}

	strategy2 := &model.Strategy{
		Frida: false, DexLevel: model.DexLevelLow, SoShell: model.SoShellNone,
		SoStrength: 0, TargetSos: []string{}, RootDetect: false, UpdatedBy: 2,
	}
	if err := repo.Save(strategy2); err != nil {
		t.Fatalf("second Save() error = %v", err)
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
