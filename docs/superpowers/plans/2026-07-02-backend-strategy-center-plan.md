# BeetleShield Backend — Strategy Center Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single global hardening-strategy record (read/write, admin-only writes) plus a query endpoint for the three built-in preset templates (finance/game/basic) to the already-merged BeetleShield backend.

**Architecture:** Same `handler → service → repository → model` layering as the app-management and user-management modules already in the codebase. `StrategyRepository` treats the `strategies` table as always holding at most one row (the "current" global strategy); `StrategyService` adds the three preset templates as in-code constants plus validation; `StrategyHandler` exposes it all under `/api/v1/strategies`, with reads open to any authenticated role and writes gated to `admin`.

**Tech Stack:** Same as the existing codebase — Go, Gin, GORM/PostgreSQL, no new dependencies. `TargetSos []string` is persisted via GORM's built-in `serializer:json` tag (no `lib/pq` or other new package needed).

Reference spec: [`docs/superpowers/specs/2026-07-02-backend-strategy-center-design.md`](../specs/2026-07-02-backend-strategy-center-design.md)

## Global Constraints

- Module name: `beetleshield-backend`. API prefix `/api/v1`; every response uses `{code int, message string, data any}` (code `0` = success) via `internal/pkg/response`.
- Local dev Postgres: `root`/`root`@`localhost:5432`/`beetleshield` (pre-existing `pg12-dev` container — do not run `make dev-up`/`docker compose up`). The shared DB is not pristine (real seed admin account and other leftover data from earlier sub-projects exist); scope test data/assertions accordingly (unique emails/prefixes, not table-wide counts) as established in the prior sub-project.
- Route table (from the spec):
  - `GET /strategies/templates`, `GET /strategies/current` → any authenticated role (`admin`/`developer`/`auditor`)
  - `PUT /strategies/current` → `admin` only
- `strategies` table holds at most one row, representing the current global strategy. `GetCurrent` returns the finance-template defaults (not persisted) when no row exists yet. `Save` always fully overwrites the single row — no partial-field PATCH semantics.
- No multi-strategy / per-client strategy support in this sub-project — explicitly deferred (see spec).
- `TargetSos` is a plain `[]string`, no server-side whitelist validation against known `.so` filenames.
- Preset template values (verbatim from the frontend's `templates` object):
  - `finance`: frida=true, xposed=true, debugger=true, emulator=true, dexLevel=high, stringEncrypt=true, resMix=true, soShell=vmp, soStrength=90, targetSos=[libnative-lib.so, libsec.so], rootDetect=true, signature=true, antiHook=true, resEncrypt=true
  - `game`: frida=true, xposed=false, debugger=true, emulator=false, dexLevel=medium, stringEncrypt=true, resMix=false, soShell=aes, soStrength=70, targetSos=[libunity.so, libmain.so], rootDetect=true, signature=true, antiHook=true, resEncrypt=false
  - `basic`: frida=true, xposed=false, debugger=true, emulator=false, dexLevel=low, stringEncrypt=false, resMix=false, soShell=none, soStrength=30, targetSos=[], rootDetect=false, signature=true, antiHook=false, resEncrypt=false

---

## File Structure

```
internal/
├── model/
│   └── strategy.go            (new)
├── db/
│   ├── db.go                  (modify — add &model.Strategy{} to Migrate)
│   └── db_test.go             (modify — append TestMigrate_StrategiesTable)
├── repository/
│   ├── strategy_repository.go      (new)
│   └── strategy_repository_test.go (new)
├── service/
│   ├── strategy_service.go      (new)
│   └── strategy_service_test.go (new)
├── handler/
│   ├── strategy_handler.go      (new)
│   └── strategy_handler_test.go (new)
└── router/
    └── router.go                 (modify — /strategies group)
cmd/server/main.go                 (modify — wire StrategyRepository/Service/Handler)
```

---

### Task 1: Strategy model and migration

**Files:**
- Create: `internal/model/strategy.go`
- Modify: `internal/db/db.go`
- Modify: `internal/db/db_test.go`

**Interfaces:**
- Produces: `model.SoShellType` (`SoShellNone`, `SoShellAES`, `SoShellVMP`, `SoShellCustomSo`), `model.DexObfuscationLevel` (`DexLevelLow`, `DexLevelMedium`, `DexLevelHigh`), `model.Strategy` struct — consumed by `internal/repository/strategy_repository.go` (Task 2).

- [ ] **Step 1: Write the model**

Create `internal/model/strategy.go`:

```go
package model

import "time"

type SoShellType string

const (
	SoShellNone     SoShellType = "none"
	SoShellAES      SoShellType = "aes"
	SoShellVMP      SoShellType = "vmp"
	SoShellCustomSo SoShellType = "custom_so"
)

type DexObfuscationLevel string

const (
	DexLevelLow    DexObfuscationLevel = "low"
	DexLevelMedium DexObfuscationLevel = "medium"
	DexLevelHigh   DexObfuscationLevel = "high"
)

type Strategy struct {
	ID            uint                `gorm:"primaryKey" json:"id"`
	Frida         bool                `json:"frida"`
	Xposed        bool                `json:"xposed"`
	Debugger      bool                `json:"debugger"`
	Emulator      bool                `json:"emulator"`
	DexLevel      DexObfuscationLevel `gorm:"size:20" json:"dexLevel"`
	StringEncrypt bool                `json:"stringEncrypt"`
	ResMix        bool                `json:"resMix"`
	SoShell       SoShellType         `gorm:"size:20" json:"soShell"`
	SoStrength    int                 `json:"soStrength"`
	TargetSos     []string            `gorm:"serializer:json" json:"targetSos"`
	RootDetect    bool                `json:"rootDetect"`
	Signature     bool                `json:"signature"`
	AntiHook      bool                `json:"antiHook"`
	ResEncrypt    bool                `json:"resEncrypt"`
	UpdatedBy     uint                `json:"updatedBy"`
	CreatedAt     time.Time           `json:"createdAt"`
	UpdatedAt     time.Time           `json:"updatedAt"`
}

func (Strategy) TableName() string {
	return "strategies"
}
```

- [ ] **Step 2: Write the failing test**

Append to `internal/db/db_test.go`:

```go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/db/... -v -run TestMigrate_StrategiesTable`
Expected: FAIL — `relation "strategies" does not exist` (Migrate doesn't create it yet).

- [ ] **Step 4: Add Strategy to AutoMigrate**

Modify `internal/db/db.go`, change the `Migrate` function:

```go
func Migrate(database *gorm.DB) error {
	return database.AutoMigrate(&model.User{}, &model.App{}, &model.Strategy{})
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/... -v`
Expected: PASS (all tests in the package, including the pre-existing `TestMigrateAndSeedAdmin` and `TestMigrate_AppsTable`, plus the new `TestMigrate_StrategiesTable`)

- [ ] **Step 6: Commit**

```bash
git add internal/model/strategy.go internal/db/db.go internal/db/db_test.go
git commit -m "feat: add Strategy model and migration"
```

---

### Task 2: Strategy repository

**Files:**
- Create: `internal/repository/strategy_repository.go`
- Test: `internal/repository/strategy_repository_test.go`

**Interfaces:**
- Consumes: `model.Strategy` (Task 1).
- Produces: `repository.StrategyRepository` with `NewStrategyRepository(db *gorm.DB) *StrategyRepository`, `GetCurrent() (*model.Strategy, error)` (returns `gorm.ErrRecordNotFound` when no row exists), `Save(strategy *model.Strategy) error` (upsert — creates the first row, or fully overwrites the existing one including zero-valued fields) — consumed by `internal/service/strategy_service.go` (Task 3).

- [ ] **Step 1: Write the failing test**

Create `internal/repository/strategy_repository_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repository/... -v -run TestStrategyRepository`
Expected: FAIL — `StrategyRepository` undefined.

- [ ] **Step 3: Implement**

Create `internal/repository/strategy_repository.go`:

```go
package repository

import (
	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type StrategyRepository struct {
	db *gorm.DB
}

func NewStrategyRepository(db *gorm.DB) *StrategyRepository {
	return &StrategyRepository{db: db}
}

func (r *StrategyRepository) GetCurrent() (*model.Strategy, error) {
	var strategy model.Strategy
	if err := r.db.Order("id ASC").First(&strategy).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}

func (r *StrategyRepository) Save(strategy *model.Strategy) error {
	var existing model.Strategy
	err := r.db.Order("id ASC").First(&existing).Error
	if err == nil {
		strategy.ID = existing.ID
	} else if err != gorm.ErrRecordNotFound {
		return err
	}
	return r.db.Save(strategy).Error
}
```

Note: `Save` reuses the existing row's ID (if any) before calling `r.db.Save(strategy)`. GORM's `Save` performs a full-row `UPDATE` (including zero-valued fields) when the struct's primary key is set, which is what correctly persists `false`/`0`/empty-slice values on the second save — unlike `Updates(struct)`, which silently skips zero-valued fields.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repository/... -v`
Expected: PASS (all repository tests, including the pre-existing `TestAppRepository_*`/`TestUserRepository_*` and the new `TestStrategyRepository_*`)

- [ ] **Step 5: Commit**

```bash
git add internal/repository/strategy_repository.go internal/repository/strategy_repository_test.go
git commit -m "feat: add strategy repository (single-row get/save)"
```

---

### Task 3: Strategy service (templates + validation)

**Files:**
- Create: `internal/service/strategy_service.go`
- Test: `internal/service/strategy_service_test.go`

**Interfaces:**
- Consumes: `repository.StrategyRepository` (Task 2), `model.Strategy`/`DexObfuscationLevel`/`SoShellType` (Task 1).
- Produces: `service.SaveStrategyInput{Frida, Xposed, Debugger, Emulator, StringEncrypt, ResMix, RootDetect, Signature, AntiHook, ResEncrypt bool; DexLevel model.DexObfuscationLevel; SoShell model.SoShellType; SoStrength int; TargetSos []string}`, `service.StrategyService` with `NewStrategyService(strategyRepo *repository.StrategyRepository) *StrategyService`, `Templates() map[string]model.Strategy`, `GetCurrent() (*model.Strategy, error)`, `Save(input SaveStrategyInput, updatedBy uint) (*model.Strategy, error)`, and sentinel errors `ErrInvalidDexLevel`, `ErrInvalidSoShell`, `ErrInvalidSoStrength` — consumed by `internal/handler/strategy_handler.go` (Task 4).

- [ ] **Step 1: Write the failing test**

Create `internal/service/strategy_service_test.go`:

```go
package service_test

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func setupTestStrategyRepo(t *testing.T) *repository.StrategyRepository {
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
	return repository.NewStrategyRepository(database)
}

func TestStrategyService_Templates(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo)

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
	svc := service.NewStrategyService(repo)

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
	svc := service.NewStrategyService(repo)

	_, err := svc.Save(service.SaveStrategyInput{
		DexLevel: "not-a-real-level", SoShell: model.SoShellNone, SoStrength: 50,
	}, 1)
	if err != service.ErrInvalidDexLevel {
		t.Errorf("err = %v, want %v", err, service.ErrInvalidDexLevel)
	}

	_, err = svc.Save(service.SaveStrategyInput{
		DexLevel: model.DexLevelLow, SoShell: "not-a-real-shell", SoStrength: 50,
	}, 1)
	if err != service.ErrInvalidSoShell {
		t.Errorf("err = %v, want %v", err, service.ErrInvalidSoShell)
	}

	_, err = svc.Save(service.SaveStrategyInput{
		DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, SoStrength: 150,
	}, 1)
	if err != service.ErrInvalidSoStrength {
		t.Errorf("err = %v, want %v", err, service.ErrInvalidSoStrength)
	}
}

func TestStrategyService_SaveThenGetCurrent(t *testing.T) {
	repo := setupTestStrategyRepo(t)
	svc := service.NewStrategyService(repo)

	saved, err := svc.Save(service.SaveStrategyInput{
		Frida: true, DexLevel: model.DexLevelMedium, SoShell: model.SoShellAES,
		SoStrength: 70, TargetSos: []string{"libunity.so"}, RootDetect: true,
	}, 42)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -v -run TestStrategyService`
Expected: FAIL — `service.NewStrategyService` undefined.

- [ ] **Step 3: Implement**

Create `internal/service/strategy_service.go`:

```go
package service

import (
	"errors"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

var (
	ErrInvalidDexLevel   = errors.New("invalid dex obfuscation level")
	ErrInvalidSoShell    = errors.New("invalid so shell type")
	ErrInvalidSoStrength = errors.New("so strength must be between 0 and 100")
)

type SaveStrategyInput struct {
	Frida         bool
	Xposed        bool
	Debugger      bool
	Emulator      bool
	DexLevel      model.DexObfuscationLevel
	StringEncrypt bool
	ResMix        bool
	SoShell       model.SoShellType
	SoStrength    int
	TargetSos     []string
	RootDetect    bool
	Signature     bool
	AntiHook      bool
	ResEncrypt    bool
}

var templates = map[string]model.Strategy{
	"finance": {
		Frida: true, Xposed: true, Debugger: true, Emulator: true,
		DexLevel: model.DexLevelHigh, StringEncrypt: true, ResMix: true,
		SoShell: model.SoShellVMP, SoStrength: 90,
		TargetSos:  []string{"libnative-lib.so", "libsec.so"},
		RootDetect: true, Signature: true, AntiHook: true, ResEncrypt: true,
	},
	"game": {
		Frida: true, Xposed: false, Debugger: true, Emulator: false,
		DexLevel: model.DexLevelMedium, StringEncrypt: true, ResMix: false,
		SoShell: model.SoShellAES, SoStrength: 70,
		TargetSos:  []string{"libunity.so", "libmain.so"},
		RootDetect: true, Signature: true, AntiHook: true, ResEncrypt: false,
	},
	"basic": {
		Frida: true, Xposed: false, Debugger: true, Emulator: false,
		DexLevel: model.DexLevelLow, StringEncrypt: false, ResMix: false,
		SoShell: model.SoShellNone, SoStrength: 30,
		TargetSos:  []string{},
		RootDetect: false, Signature: true, AntiHook: false, ResEncrypt: false,
	},
}

var validDexLevels = map[model.DexObfuscationLevel]bool{
	model.DexLevelLow:    true,
	model.DexLevelMedium: true,
	model.DexLevelHigh:   true,
}

var validSoShells = map[model.SoShellType]bool{
	model.SoShellNone:     true,
	model.SoShellAES:      true,
	model.SoShellVMP:      true,
	model.SoShellCustomSo: true,
}

type StrategyService struct {
	strategyRepo *repository.StrategyRepository
}

func NewStrategyService(strategyRepo *repository.StrategyRepository) *StrategyService {
	return &StrategyService{strategyRepo: strategyRepo}
}

func (s *StrategyService) Templates() map[string]model.Strategy {
	return templates
}

func (s *StrategyService) GetCurrent() (*model.Strategy, error) {
	current, err := s.strategyRepo.GetCurrent()
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			defaultStrategy := templates["finance"]
			return &defaultStrategy, nil
		}
		return nil, err
	}
	return current, nil
}

func (s *StrategyService) Save(input SaveStrategyInput, updatedBy uint) (*model.Strategy, error) {
	if !validDexLevels[input.DexLevel] {
		return nil, ErrInvalidDexLevel
	}
	if !validSoShells[input.SoShell] {
		return nil, ErrInvalidSoShell
	}
	if input.SoStrength < 0 || input.SoStrength > 100 {
		return nil, ErrInvalidSoStrength
	}

	strategy := &model.Strategy{
		Frida: input.Frida, Xposed: input.Xposed, Debugger: input.Debugger, Emulator: input.Emulator,
		DexLevel: input.DexLevel, StringEncrypt: input.StringEncrypt, ResMix: input.ResMix,
		SoShell: input.SoShell, SoStrength: input.SoStrength, TargetSos: input.TargetSos,
		RootDetect: input.RootDetect, Signature: input.Signature, AntiHook: input.AntiHook, ResEncrypt: input.ResEncrypt,
		UpdatedBy: updatedBy,
	}
	if err := s.strategyRepo.Save(strategy); err != nil {
		return nil, err
	}
	return strategy, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/service/... -v -run TestStrategyService`
Expected: PASS (`TestStrategyService_Templates`, `TestStrategyService_GetCurrent_DefaultsToFinanceWhenUnsaved`, `TestStrategyService_Save_ValidationErrors`, `TestStrategyService_SaveThenGetCurrent`)

- [ ] **Step 5: Commit**

```bash
git add internal/service/strategy_service.go internal/service/strategy_service_test.go
git commit -m "feat: add strategy service with templates and validation"
```

---

### Task 4: Strategy handler, router wiring, main.go wiring

**Files:**
- Create: `internal/handler/strategy_handler.go`
- Test: `internal/handler/strategy_handler_test.go`
- Modify: `internal/router/router.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `service.StrategyService`/`SaveStrategyInput` (Task 3), `middleware.RequireRole` (existing), `middleware.ContextUserIDKey` (existing), `response.Success`/`Error` (existing).
- Produces: `handler.StrategyHandler` with `NewStrategyHandler(strategyService *service.StrategyService) *StrategyHandler`, `Templates`, `GetCurrent`, `SaveCurrent` (all `func(c *gin.Context)`) — wired into `router.Deps.StrategyHandler` (new field alongside the existing `JWTSecret`/`AuthHandler`/`AppHandler`/`UserHandler`).

- [ ] **Step 1: Write the failing end-to-end test**

Create `internal/handler/strategy_handler_test.go`:

```go
package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func setupStrategyRouter(t *testing.T) (*httptest.Server, string, string, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	hashed, _ := hash.HashPassword("Password123!")
	adminUser := model.User{
		Name: "策略接口管理员", Email: "strategyhandler-admin@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(adminUser.Email)
	if err := userRepo.Create(&adminUser); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	developerUser := model.User{
		Name: "策略接口开发者", Email: "strategyhandler-developer@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(developerUser.Email)
	if err := userRepo.Create(&developerUser); err != nil {
		t.Fatalf("create developer user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	adminToken, _, err := authService.Login(adminUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("admin Login() error = %v", err)
	}
	developerToken, _, err := authService.Login(developerUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("developer Login() error = %v", err)
	}
	authHandler := handler.NewAuthHandler(authService)

	strategyRepo := repository.NewStrategyRepository(database)
	strategyService := service.NewStrategyService(strategyRepo)
	strategyHandler := handler.NewStrategyHandler(strategyService)

	r := router.New(router.Deps{
		JWTSecret:       cfg.JWTSecret,
		AuthHandler:     authHandler,
		StrategyHandler: strategyHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(adminUser.Email)
		userRepo.DeleteByEmail(developerUser.Email)
		database.Unscoped().Where("1 = 1").Delete(&model.Strategy{})
		srv.Close()
	}
	return srv, adminToken, developerToken, cleanup
}

func TestStrategyTemplates_AnyAuthenticatedRole(t *testing.T) {
	srv, _, developerToken, cleanup := setupStrategyRouter(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies/templates", nil)
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("templates request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("templates status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var tplResp struct {
		Data map[string]model.Strategy `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tplResp); err != nil {
		t.Fatalf("decode templates response: %v", err)
	}
	if len(tplResp.Data) != 3 {
		t.Fatalf("expected 3 templates, got %d", len(tplResp.Data))
	}
}

func TestStrategySaveCurrent_AdminSucceedsThenGetCurrentReflectsIt(t *testing.T) {
	srv, adminToken, _, cleanup := setupStrategyRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"frida": true, "xposed": false, "debugger": true, "emulator": false,
		"dexLevel": "medium", "stringEncrypt": true, "resMix": false,
		"soShell": "aes", "soStrength": 70, "targetSos": []string{"libunity.so"},
		"rootDetect": true, "signature": true, "antiHook": true, "resEncrypt": false,
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/strategies/current", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	getReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/strategies/current", nil)
	getReq.Header.Set("Authorization", "Bearer "+adminToken)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get current request: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get current status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}

	var currentResp struct {
		Data model.Strategy `json:"data"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&currentResp); err != nil {
		t.Fatalf("decode get current response: %v", err)
	}
	if currentResp.Data.DexLevel != model.DexLevelMedium || currentResp.Data.SoStrength != 70 {
		t.Errorf("GetCurrent() after save did not reflect saved values: %+v", currentResp.Data)
	}
}

func TestStrategySaveCurrent_RequiresAdminRole(t *testing.T) {
	srv, _, developerToken, cleanup := setupStrategyRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{
		"dexLevel": "low", "soShell": "none", "soStrength": 30,
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/strategies/current", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("save status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/handler/... -v -run TestStrategy`
Expected: FAIL — package doesn't compile (`handler.NewStrategyHandler`, `router.Deps.StrategyHandler` undefined).

- [ ] **Step 3: Implement the strategy handler**

Create `internal/handler/strategy_handler.go`:

```go
package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/service"
)

type StrategyHandler struct {
	strategyService *service.StrategyService
}

func NewStrategyHandler(strategyService *service.StrategyService) *StrategyHandler {
	return &StrategyHandler{strategyService: strategyService}
}

func (h *StrategyHandler) Templates(c *gin.Context) {
	response.Success(c, http.StatusOK, h.strategyService.Templates())
}

func (h *StrategyHandler) GetCurrent(c *gin.Context) {
	current, err := h.strategyService.GetCurrent()
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50009, "查询当前策略失败")
		return
	}
	response.Success(c, http.StatusOK, current)
}

type saveStrategyRequest struct {
	Frida         bool                      `json:"frida"`
	Xposed        bool                      `json:"xposed"`
	Debugger      bool                      `json:"debugger"`
	Emulator      bool                      `json:"emulator"`
	DexLevel      model.DexObfuscationLevel `json:"dexLevel" binding:"required"`
	StringEncrypt bool                      `json:"stringEncrypt"`
	ResMix        bool                      `json:"resMix"`
	SoShell       model.SoShellType         `json:"soShell" binding:"required"`
	SoStrength    int                       `json:"soStrength"`
	TargetSos     []string                  `json:"targetSos"`
	RootDetect    bool                      `json:"rootDetect"`
	Signature     bool                      `json:"signature"`
	AntiHook      bool                      `json:"antiHook"`
	ResEncrypt    bool                      `json:"resEncrypt"`
}

func (h *StrategyHandler) SaveCurrent(c *gin.Context) {
	var req saveStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40011, err.Error())
		return
	}

	userID := c.GetUint(middleware.ContextUserIDKey)

	saved, err := h.strategyService.Save(service.SaveStrategyInput{
		Frida: req.Frida, Xposed: req.Xposed, Debugger: req.Debugger, Emulator: req.Emulator,
		DexLevel: req.DexLevel, StringEncrypt: req.StringEncrypt, ResMix: req.ResMix,
		SoShell: req.SoShell, SoStrength: req.SoStrength, TargetSos: req.TargetSos,
		RootDetect: req.RootDetect, Signature: req.Signature, AntiHook: req.AntiHook, ResEncrypt: req.ResEncrypt,
	}, userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidDexLevel):
			response.Error(c, http.StatusBadRequest, 40012, err.Error())
		case errors.Is(err, service.ErrInvalidSoShell):
			response.Error(c, http.StatusBadRequest, 40013, err.Error())
		case errors.Is(err, service.ErrInvalidSoStrength):
			response.Error(c, http.StatusBadRequest, 40014, err.Error())
		default:
			response.Error(c, http.StatusInternalServerError, 50010, "保存策略失败")
		}
		return
	}

	response.Success(c, http.StatusOK, saved)
}
```

- [ ] **Step 4: Wire the `/strategies` routes into the router**

Modify `internal/router/router.go` — full new file content:

```go
package router

import (
	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
)

type Deps struct {
	JWTSecret       string
	AuthHandler     *handler.AuthHandler
	AppHandler      *handler.AppHandler
	UserHandler     *handler.UserHandler
	StrategyHandler *handler.StrategyHandler
}

func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", deps.AuthHandler.Login)
			auth.GET("/me", middleware.JWTAuth(deps.JWTSecret), deps.AuthHandler.Me)
		}

		writeRoles := middleware.RequireRole(model.RoleAdmin, model.RoleDeveloper)

		apps := v1.Group("/apps")
		apps.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			apps.POST("/upload", writeRoles, deps.AppHandler.Upload)
			apps.GET("", deps.AppHandler.List)
			apps.GET("/:id", deps.AppHandler.Get)
			apps.DELETE("/:id", writeRoles, deps.AppHandler.Delete)
			apps.GET("/:id/download-url", writeRoles, deps.AppHandler.DownloadURL)
		}

		users := v1.Group("/users")
		users.Use(middleware.JWTAuth(deps.JWTSecret), middleware.RequireRole(model.RoleAdmin))
		{
			users.GET("", deps.UserHandler.List)
			users.POST("", deps.UserHandler.Create)
			users.PATCH("/:id", deps.UserHandler.Update)
			users.PATCH("/:id/status", deps.UserHandler.UpdateStatus)
		}

		strategies := v1.Group("/strategies")
		strategies.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			strategies.GET("/templates", deps.StrategyHandler.Templates)
			strategies.GET("/current", deps.StrategyHandler.GetCurrent)
			strategies.PUT("/current", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.SaveCurrent)
		}
	}

	return r
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/handler/... -v -run TestStrategy`
Expected: PASS (`TestStrategyTemplates_AnyAuthenticatedRole`, `TestStrategySaveCurrent_AdminSucceedsThenGetCurrentReflectsIt`, `TestStrategySaveCurrent_RequiresAdminRole`)

- [ ] **Step 6: Wire `StrategyService`/`StrategyHandler` into `main.go`**

Modify `cmd/server/main.go` — full new file content:

```go
package main

import (
	"context"
	"log"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func main() {
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	database, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := db.Migrate(database); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	if err := db.SeedAdmin(database, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("failed to seed admin account: %v", err)
	}

	storageClient, err := storage.NewMinioStorage(cfg.MinioEndpoint, cfg.MinioAccessKey, cfg.MinioSecretKey, cfg.MinioBucket, cfg.MinioUseSSL)
	if err != nil {
		log.Fatalf("failed to init storage client: %v", err)
	}
	if err := storageClient.EnsureBucket(context.Background()); err != nil {
		log.Fatalf("failed to ensure minio bucket: %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	authHandler := handler.NewAuthHandler(authService)

	userService := service.NewUserService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	appRepo := repository.NewAppRepository(database)
	appService := service.NewAppService(appRepo, storageClient, cfg.MaxUploadSizeMB)
	appHandler := handler.NewAppHandler(appService)

	strategyRepo := repository.NewStrategyRepository(database)
	strategyService := service.NewStrategyService(strategyRepo)
	strategyHandler := handler.NewStrategyHandler(strategyService)

	r := router.New(router.Deps{
		JWTSecret:       cfg.JWTSecret,
		AuthHandler:     authHandler,
		AppHandler:      appHandler,
		UserHandler:     userHandler,
		StrategyHandler: strategyHandler,
	})

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
```

- [ ] **Step 7: Manually verify with curl**

```bash
go run ./cmd/server &
sleep 1
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@beetleshield.com","password":"ChangeMe123!"}' | jq -r '.data.token')
curl -s http://localhost:8080/api/v1/strategies/templates -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8080/api/v1/strategies/current -H "Authorization: Bearer $TOKEN"
kill %1
```

Expected: both responses have `"code":0`; `templates` returns an object with `finance`/`game`/`basic` keys; `current` returns the finance-template defaults (no strategy saved yet on a fresh DB).

- [ ] **Step 8: Run the full project test suite**

```bash
go test ./... -count=1 -v
```

Expected: every package reports `ok`, no failures anywhere in the repo.

- [ ] **Step 9: Commit**

```bash
git add internal/handler/strategy_handler.go internal/handler/strategy_handler_test.go internal/router/router.go cmd/server/main.go
git commit -m "feat: wire strategy center endpoints through router and main"
```

---

## Post-plan note

This completes sub-project three (strategy center). The next sub-projects, in the order recorded in the base design spec, are: hardening pipeline (engine integration), reports, log audit, and the dashboard aggregation endpoints — each should go through its own brainstorming → spec → plan cycle rather than being bolted onto this one.
