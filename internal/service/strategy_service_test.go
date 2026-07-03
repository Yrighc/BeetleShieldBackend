package service_test

import (
	"errors"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
	"gorm.io/gorm"
)

func setupTestStrategyRepo(t *testing.T) *repository.StrategyRepository {
	t.Helper()
	repo, _ := setupTestStrategyRepoWithDB(t)
	return repo
}

func setupTestStrategyRepoWithDB(t *testing.T) (*repository.StrategyRepository, *gorm.DB) {
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
	return repository.NewStrategyRepository(database), database
}

func TestStrategyService_Templates(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	tpls := svc.Templates()
	if len(tpls) != 3 {
		t.Fatalf("expected 3 templates, got %d", len(tpls))
	}
	finance, ok := tpls["finance"]
	if !ok || finance.DexLevel != model.DexLevelHigh || finance.SoStrength != 90 {
		t.Errorf("unexpected finance template: %+v", finance)
	}
	game, ok := tpls["game"]
	if !ok || game.SoShell != model.SoShellAES || game.SoStrength != 70 {
		t.Errorf("unexpected game template: %+v", game)
	}
	basic, ok := tpls["basic"]
	if !ok || basic.SoShell != model.SoShellNone || len(basic.TargetSos) != 0 {
		t.Errorf("unexpected basic template: %+v", basic)
	}
}

func TestStrategyService_GetCurrent_DefaultsToFinanceWhenUnsaved(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	current, err := svc.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() error = %v", err)
	}
	if current.DexLevel != model.DexLevelHigh || current.SoStrength != 90 {
		t.Errorf("expected finance-template defaults, got: %+v", current)
	}
}

func TestStrategyService_Save_ValidationErrors(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	_, err := svc.Save(service.SaveStrategyInput{
		DexLevel: "not-a-real-level", SoShell: model.SoShellNone, SoStrength: 50,
	}, 1, "")
	if err != service.ErrInvalidDexLevel {
		t.Errorf("err = %v, want %v", err, service.ErrInvalidDexLevel)
	}

	_, err = svc.Save(service.SaveStrategyInput{
		DexLevel: model.DexLevelLow, SoShell: "not-a-real-shell", SoStrength: 50,
	}, 1, "")
	if err != service.ErrInvalidSoShell {
		t.Errorf("err = %v, want %v", err, service.ErrInvalidSoShell)
	}

	_, err = svc.Save(service.SaveStrategyInput{
		DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, SoStrength: 150,
	}, 1, "")
	if err != service.ErrInvalidSoStrength {
		t.Errorf("err = %v, want %v", err, service.ErrInvalidSoStrength)
	}
}

func TestStrategyService_SaveThenGetCurrent(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	saved, err := svc.Save(service.SaveStrategyInput{
		Frida: true, DexLevel: model.DexLevelMedium, SoShell: model.SoShellAES,
		SoStrength: 70, TargetSos: []string{"libunity.so"}, RootDetect: true,
	}, 42, "")
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if saved.UpdatedBy != 42 {
		t.Errorf("UpdatedBy = %d, want 42", saved.UpdatedBy)
	}

	current, err := svc.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() error = %v", err)
	}
	if current.DexLevel != model.DexLevelMedium || current.SoStrength != 70 {
		t.Errorf("GetCurrent() after Save() returned unexpected values: %+v", current)
	}
	if !current.IsDefault || current.Name != "默认加固策略" {
		t.Errorf("current metadata = %+v", current)
	}
}

func TestStrategyService_GetCurrentPromotesLegacyRow(t *testing.T) {
	repo, database := setupTestStrategyRepoWithDB(t)
	svc := service.NewStrategyService(repo, nil)

	legacy := &model.Strategy{
		DexLevel: model.DexLevelMedium, SoShell: model.SoShellAES,
		SoStrength: 70, UpdatedBy: 99,
	}
	if err := database.Create(legacy).Error; err != nil {
		t.Fatalf("create legacy strategy: %v", err)
	}

	current, err := svc.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() error = %v", err)
	}
	if current.ID != legacy.ID || !current.IsDefault || current.Name != "默认加固策略" {
		t.Fatalf("current = %+v, want promoted legacy row", current)
	}
}

func TestStrategyService_CreateUpdateListDeleteRegularStrategy(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	created, err := svc.Create(service.StrategyPayloadInput{
		Name:        "数信学院加固策略",
		Description: "高强度配置",
		SaveStrategyInput: service.SaveStrategyInput{
			Frida: true, DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP,
			SoStrength: 90, TargetSos: []string{"libnative-lib.so"}, RootDetect: true,
		},
	}, 17, "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == 0 || created.IsDefault || created.CreatedBy != 17 || created.UpdatedBy != 17 {
		t.Fatalf("created = %+v", created)
	}

	items, total, err := svc.List(repository.StrategyListFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "数信学院加固策略" {
		t.Fatalf("List() = %+v total=%d", items, total)
	}

	found, err := svc.Get(created.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("Get() ID = %d, want %d", found.ID, created.ID)
	}

	updated, err := svc.Update(created.ID, service.StrategyPayloadInput{
		Name:        "数信学院兼容策略",
		Description: "兼容性优先",
		SaveStrategyInput: service.SaveStrategyInput{
			DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, SoStrength: 30,
			Signature: true,
		},
	}, 23, "")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if updated.Name != "数信学院兼容策略" || updated.UpdatedBy != 23 || updated.DexLevel != model.DexLevelLow {
		t.Fatalf("updated = %+v", updated)
	}

	if err := svc.Delete(created.ID, 23, ""); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := svc.Get(created.ID); !errors.Is(err, service.ErrStrategyNotFound) {
		t.Fatalf("Get(deleted) err = %v, want ErrStrategyNotFound", err)
	}
}

func TestStrategyService_RegularStrategyValidation(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	_, err := svc.Create(service.StrategyPayloadInput{
		SaveStrategyInput: service.SaveStrategyInput{DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, SoStrength: 30},
	}, 1, "")
	if !errors.Is(err, service.ErrStrategyNameRequired) {
		t.Fatalf("Create(empty name) err = %v, want ErrStrategyNameRequired", err)
	}

	_, err = svc.Create(service.StrategyPayloadInput{
		Name: "重复策略",
		SaveStrategyInput: service.SaveStrategyInput{
			DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, SoStrength: 30,
		},
	}, 1, "")
	if err != nil {
		t.Fatalf("Create(first) error = %v", err)
	}
	_, err = svc.Create(service.StrategyPayloadInput{
		Name: "重复策略",
		SaveStrategyInput: service.SaveStrategyInput{
			DexLevel: model.DexLevelMedium, SoShell: model.SoShellAES, SoStrength: 70,
		},
	}, 1, "")
	if !errors.Is(err, service.ErrStrategyNameExists) {
		t.Fatalf("Create(duplicate) err = %v, want ErrStrategyNameExists", err)
	}
}

func TestStrategyService_DeleteDefaultRejected(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	current, err := svc.SaveCurrent(service.SaveStrategyInput{
		DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, SoStrength: 90,
	}, 1, "")
	if err != nil {
		t.Fatalf("SaveCurrent() error = %v", err)
	}

	err = svc.Delete(current.ID, 1, "")
	if !errors.Is(err, service.ErrDefaultStrategyDelete) {
		t.Fatalf("Delete(default) err = %v, want ErrDefaultStrategyDelete", err)
	}
}

func TestStrategyService_ResolveForHardening(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo, nil)

	defaultStrategy, err := svc.SaveCurrent(service.SaveStrategyInput{
		DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, SoStrength: 90,
	}, 1, "")
	if err != nil {
		t.Fatalf("SaveCurrent() error = %v", err)
	}
	regular, err := svc.Create(service.StrategyPayloadInput{
		Name: "数信学院加固策略",
		SaveStrategyInput: service.SaveStrategyInput{
			DexLevel: model.DexLevelMedium, SoShell: model.SoShellAES, SoStrength: 70,
		},
	}, 2, "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	resolved, name, err := svc.ResolveForHardening(0)
	if err != nil {
		t.Fatalf("ResolveForHardening(0) error = %v", err)
	}
	if resolved.ID != defaultStrategy.ID || name != "默认加固策略" {
		t.Fatalf("ResolveForHardening(0) = %+v %q", resolved, name)
	}

	resolved, name, err = svc.ResolveForHardening(regular.ID)
	if err != nil {
		t.Fatalf("ResolveForHardening(regular) error = %v", err)
	}
	if resolved.ID != regular.ID || name != regular.Name || resolved.DexLevel != model.DexLevelMedium {
		t.Fatalf("ResolveForHardening(regular) = %+v %q", resolved, name)
	}

	resolved, name, err = svc.ResolveForHardening(defaultStrategy.ID)
	if err != nil {
		t.Fatalf("ResolveForHardening(default ID) error = %v", err)
	}
	if resolved.ID != defaultStrategy.ID || name != "默认加固策略" {
		t.Fatalf("ResolveForHardening(default ID) = %+v %q", resolved, name)
	}

	_, _, err = svc.ResolveForHardening(99999999)
	if !errors.Is(err, service.ErrStrategyNotFound) {
		t.Fatalf("ResolveForHardening(missing) err = %v, want ErrStrategyNotFound", err)
	}
}

func TestStrategyService_SaveInvalidDexLevelRecordsFailureAudit(t *testing.T) {
	repo, database := setupTestStrategyRepoWithDB(t)
	auditService := service.NewAuditService(repository.NewAuditRepository(database))
	svc := service.NewStrategyService(repo, auditService)

	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 800_000)
	t.Cleanup(func() {
		database.Unscoped().Where("actor_user_id = ?", actorID).Delete(&model.AuditLog{})
	})

	_, err := svc.Save(service.SaveStrategyInput{
		DexLevel: "not-a-real-level", SoShell: model.SoShellNone, SoStrength: 50,
	}, actorID, "")
	if err != service.ErrInvalidDexLevel {
		t.Fatalf("err = %v, want %v", err, service.ErrInvalidDexLevel)
	}

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionStrategySave),
		TargetType:  "strategy",
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}

	var failureRows []model.AuditLog
	for _, row := range logs {
		if !row.Success {
			failureRows = append(failureRows, row)
		}
	}
	if total != 1 || len(failureRows) != 1 {
		t.Fatalf("failure audit rows = %+v (total=%d), want exactly 1", failureRows, total)
	}
}
