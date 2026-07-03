package service_test

import (
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
