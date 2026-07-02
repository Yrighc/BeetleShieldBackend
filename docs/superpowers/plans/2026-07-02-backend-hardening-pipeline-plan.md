# BeetleShield Backend — Hardening Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an asynchronous hardening pipeline that queues existing uploaded apps, runs the local `dpt.jar` engine serially, records step/log state, and exposes task/history/artifact APIs.

**Architecture:** Follow the existing `handler -> service -> repository -> model` layering. `HardeningRepository` owns database queue, step, and log persistence; `HardeningService` owns task creation, default strategy/rules, command mapping, and read APIs; `HardeningWorker` owns serial execution using an injected engine runner and storage interface so tests never need to run the real jar.

**Tech Stack:** Go 1.22+, Gin, GORM/PostgreSQL, MinIO. No new third-party dependencies; use standard-library `os/exec`, `context`, `bufio`, `crypto/sha256`, `io`, and `os` for the worker and engine adapter.

Reference spec: [`docs/superpowers/specs/2026-07-02-backend-hardening-pipeline-design.md`](../specs/2026-07-02-backend-hardening-pipeline-design.md)

## Global Constraints

- API prefix remains `/api/v1`; every endpoint responds through `internal/pkg/response` as `{code int, message string, data any}` where `code=0` means success.
- Existing roles are `admin`, `developer`, and `auditor`. `admin/developer` may create hardening tasks; all authenticated roles may list/read tasks, logs, history, and download artifact URLs in this first version.
- dpt jar default path: `/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar`.
- Work directory default: `/tmp/beetleshield-hardening`.
- Default VMP rules text is exactly:

```text
# 全量探测保护 (依赖内置规则引擎进行智能避让)
**
```

- First version is single-process and serial: no Redis/RabbitMQ, no multi-worker concurrency, no cancel, no retry, no re-run endpoint.
- `dpt.jar` success must not rely only on exit code. A task succeeds only after the unsigned artifact exists, has size > 0, and uploads to MinIO.
- The unsigned artifact is the default delivery artifact. A signed test artifact is optional and downloadable only if the engine produced it.
- Do not rework strategy templates in this sub-project. Store `strategyName`, `strategySnapshot`, and `vmpRulesText` as execution-time snapshots.
- Tests must not execute the real `dpt.jar` by default. Worker and engine behavior are tested with fakes.
- The repository's existing integration tests use local Postgres at `root`/`root` on `localhost:5432`, database `beetleshield`; use unique package prefixes and cleanup, not whole-table assumptions.

---

## File Structure

```
internal/
├── config/
│   ├── config.go                         (modify: DPT config)
│   └── config_test.go                    (modify: DPT defaults)
├── db/
│   └── db.go                             (modify: AutoMigrate hardening models)
├── model/
│   └── hardening.go                      (create: task/step/log models and constants)
├── pkg/storage/
│   ├── minio.go                          (modify: add GetObjectToFile helper)
│   └── minio_test.go                     (modify: cover GetObjectToFile)
├── repository/
│   ├── app_repository.go                 (modify: UpdateStatus)
│   ├── hardening_repository.go           (create)
│   └── hardening_repository_test.go      (create)
├── service/
│   ├── hardening_command.go              (create: command/rules/artifact helpers)
│   ├── hardening_service.go              (create: create/read/download service)
│   ├── hardening_command_test.go         (create)
│   └── hardening_service_test.go         (create)
├── worker/
│   ├── engine.go                         (create: engine runner interfaces and dpt runner)
│   ├── hardening_worker.go               (create: serial worker orchestration)
│   └── hardening_worker_test.go          (create)
├── handler/
│   ├── hardening_handler.go              (create)
│   └── hardening_handler_test.go         (create)
└── router/
    └── router.go                         (modify: hardening routes and app history route)
cmd/server/main.go                        (modify: wire repo/service/worker/handler)
.env.example                              (modify: DPT config defaults)
README.md                                 (modify: API overview and manual smoke note)
```

---

### Task 1: Hardening Models, Config, Migration, and Storage Helper

**Files:**
- Create: `internal/model/hardening.go`
- Modify: `internal/db/db.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/pkg/storage/minio.go`
- Modify: `internal/pkg/storage/minio_test.go`
- Modify: `.env.example`

**Interfaces:**
- Produces model constants:
  - `model.HardeningTaskStatusQueued`, `model.HardeningTaskStatusRunning`, `model.HardeningTaskStatusCompleted`, `model.HardeningTaskStatusFailed`
  - `model.HardeningStepStatusWaiting`, `model.HardeningStepStatusRunning`, `model.HardeningStepStatusSuccess`, `model.HardeningStepStatusFailed`
  - `model.HardeningStepPrepareInput`, `model.HardeningStepParsePackage`, `model.HardeningStepApplyStrategy`, `model.HardeningStepRunEngine`, `model.HardeningStepCollectArtifacts`, `model.HardeningStepUploadArtifacts`
  - `model.HardeningLogLevelInfo`, `model.HardeningLogLevelWarn`, `model.HardeningLogLevelError`, `model.HardeningLogLevelSuccess`
- Produces structs: `model.HardeningTask`, `model.HardeningStep`, `model.HardeningLog`.
- Produces config fields: `DPTJarPath string`, `DPTWorkDir string`, `DPTDefaultVMPRules string`, `DPTTaskTimeoutMinutes int`.
- Produces storage method: `(*storage.MinioStorage).GetObjectToFile(ctx context.Context, objectKey string, destinationPath string) error`.
- Later tasks consume these names exactly.

- [ ] **Step 1: Write failing migration/config/storage tests**

Append this test to `internal/db/db_test.go`:

```go
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
		Name: "Hardening Migration Test",
		PackageName: "com.hardening.migration.test",
		Version: "1.0.0",
		Tag: model.AppTagTool,
		Status: model.AppStatusUnprotected,
		ObjectKey: "hardening/migration/app.apk",
		MD5: "d41d8cd98f00b204e9800998ecf8427e",
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		UploadedBy: 1,
	}
	database.Unscoped().Where("package_name = ?", app.PackageName).Delete(&model.App{})
	if err := database.Create(&app).Error; err != nil {
		t.Fatalf("create app: %v", err)
	}
	defer database.Unscoped().Where("package_name = ?", app.PackageName).Delete(&model.App{})

	task := model.HardeningTask{
		TaskNo: "TASK-MIGRATION-001",
		AppID: app.ID,
		Status: model.HardeningTaskStatusQueued,
		StrategyName: "默认加固模板",
		StrategySnapshot: model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP},
		VMPRulesText: "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		CreatedBy: 1,
	}
	database.Unscoped().Where("task_no = ?", task.TaskNo).Delete(&model.HardeningTask{})
	if err := database.Create(&task).Error; err != nil {
		t.Fatalf("create hardening task: %v", err)
	}
	defer database.Unscoped().Where("task_no = ?", task.TaskNo).Delete(&model.HardeningTask{})

	step := model.HardeningStep{
		TaskID: task.ID,
		StepKey: model.HardeningStepPrepareInput,
		Name: "准备输入",
		Status: model.HardeningStepStatusWaiting,
		SortOrder: 1,
	}
	if err := database.Create(&step).Error; err != nil {
		t.Fatalf("create hardening step: %v", err)
	}

	logLine := model.HardeningLog{
		TaskID: task.ID,
		StepID: &step.ID,
		Level: model.HardeningLogLevelInfo,
		Message: "migration log line",
	}
	if err := database.Create(&logLine).Error; err != nil {
		t.Fatalf("create hardening log: %v", err)
	}
}
```

Append this test to `internal/config/config_test.go`:

```go
func TestLoad_DPTDefaults(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := []byte("JWT_SECRET=test-secret\nDB_HOST=localhost\n")
	if err := os.WriteFile(envPath, content, 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	cfg, err := Load(envPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DPTJarPath != "/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar" {
		t.Fatalf("DPTJarPath = %q", cfg.DPTJarPath)
	}
	if cfg.DPTWorkDir != "/tmp/beetleshield-hardening" {
		t.Fatalf("DPTWorkDir = %q", cfg.DPTWorkDir)
	}
	if cfg.DPTDefaultVMPRules != "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**" {
		t.Fatalf("DPTDefaultVMPRules = %q", cfg.DPTDefaultVMPRules)
	}
	if cfg.DPTTaskTimeoutMinutes != 60 {
		t.Fatalf("DPTTaskTimeoutMinutes = %d", cfg.DPTTaskTimeoutMinutes)
	}
}
```

Append this test to `internal/pkg/storage/minio_test.go`:

```go
func TestMinioStorage_GetObjectToFile(t *testing.T) {
	st := setupMinioStorage(t)
	ctx := context.Background()
	objectKey := "hardening-storage-test/source.txt"
	body := strings.NewReader("download me")
	if err := st.PutObject(ctx, objectKey, body, int64(body.Len()), "text/plain"); err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	t.Cleanup(func() {
		_ = st.DeleteObject(ctx, objectKey)
	})

	destination := filepath.Join(t.TempDir(), "downloaded.txt")
	if err := st.GetObjectToFile(ctx, objectKey, destination); err != nil {
		t.Fatalf("GetObjectToFile() error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "download me" {
		t.Fatalf("downloaded content = %q", string(got))
	}
}
```

If imports are missing, add the exact packages used by each test: `os`, `path/filepath`, `context`, and `strings`.

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/config ./internal/db ./internal/pkg/storage -run 'TestLoad_DPTDefaults|TestMigrate_HardeningTables|TestMinioStorage_GetObjectToFile' -v
```

Expected: FAIL because `HardeningTask`, DPT config fields, and `GetObjectToFile` are not defined yet.

- [ ] **Step 3: Add hardening models**

Create `internal/model/hardening.go`:

```go
package model

import "time"

type HardeningTaskStatus string

const (
	HardeningTaskStatusQueued    HardeningTaskStatus = "queued"
	HardeningTaskStatusRunning   HardeningTaskStatus = "running"
	HardeningTaskStatusCompleted HardeningTaskStatus = "completed"
	HardeningTaskStatusFailed    HardeningTaskStatus = "failed"
)

type HardeningStepStatus string

const (
	HardeningStepStatusWaiting HardeningStepStatus = "waiting"
	HardeningStepStatusRunning HardeningStepStatus = "running"
	HardeningStepStatusSuccess HardeningStepStatus = "success"
	HardeningStepStatusFailed  HardeningStepStatus = "failed"
)

type HardeningStepKey string

const (
	HardeningStepPrepareInput     HardeningStepKey = "prepare_input"
	HardeningStepParsePackage     HardeningStepKey = "parse_package"
	HardeningStepApplyStrategy    HardeningStepKey = "apply_strategy"
	HardeningStepRunEngine        HardeningStepKey = "run_engine"
	HardeningStepCollectArtifacts HardeningStepKey = "collect_artifacts"
	HardeningStepUploadArtifacts  HardeningStepKey = "upload_artifacts"
)

type HardeningLogLevel string

const (
	HardeningLogLevelInfo    HardeningLogLevel = "info"
	HardeningLogLevelWarn    HardeningLogLevel = "warn"
	HardeningLogLevelError   HardeningLogLevel = "error"
	HardeningLogLevelSuccess HardeningLogLevel = "success"
)

type HardeningTask struct {
	ID                       uint                `gorm:"primaryKey" json:"id"`
	TaskNo                   string              `gorm:"size:40;uniqueIndex;not null" json:"taskNo"`
	AppID                    uint                `gorm:"index;not null" json:"appId"`
	App                      App                 `gorm:"foreignKey:AppID" json:"app,omitempty"`
	Status                   HardeningTaskStatus `gorm:"size:20;index;not null" json:"status"`
	StrategyName             string              `gorm:"size:120;not null" json:"strategyName"`
	StrategySnapshot         Strategy            `gorm:"serializer:json" json:"strategySnapshot"`
	VMPRulesText             string              `gorm:"type:text" json:"vmpRulesText"`
	EnableFileIntegrityCheck bool                `json:"enableFileIntegrityCheck"`
	EnableProxyDetect        bool                `json:"enableProxyDetect"`
	UnsignedObjectKey        string              `gorm:"size:500" json:"unsignedObjectKey"`
	UnsignedFileSize         int64               `json:"unsignedFileSize"`
	UnsignedSHA256           string              `gorm:"size:64" json:"unsignedSha256"`
	SignedTestObjectKey       string              `gorm:"size:500" json:"signedTestObjectKey"`
	SignedTestFileSize        int64               `json:"signedTestFileSize"`
	SignedTestSHA256          string              `gorm:"size:64" json:"signedTestSha256"`
	ErrorSummary              string              `gorm:"size:500" json:"errorSummary"`
	CreatedBy                 uint                `gorm:"not null" json:"createdBy"`
	StartedAt                 *time.Time          `json:"startedAt"`
	FinishedAt                *time.Time          `json:"finishedAt"`
	CreatedAt                 time.Time           `json:"createdAt"`
	UpdatedAt                 time.Time           `json:"updatedAt"`
}

func (HardeningTask) TableName() string {
	return "hardening_tasks"
}

type HardeningStep struct {
	ID           uint                `gorm:"primaryKey" json:"id"`
	TaskID       uint                `gorm:"index;not null" json:"taskId"`
	StepKey      HardeningStepKey    `gorm:"size:40;index;not null" json:"stepKey"`
	Name         string              `gorm:"size:80;not null" json:"name"`
	Status       HardeningStepStatus `gorm:"size:20;not null" json:"status"`
	SortOrder    int                 `gorm:"not null" json:"sortOrder"`
	StartedAt    *time.Time          `json:"startedAt"`
	FinishedAt   *time.Time          `json:"finishedAt"`
	ErrorMessage string              `gorm:"size:500" json:"errorMessage"`
	CreatedAt    time.Time           `json:"createdAt"`
	UpdatedAt    time.Time           `json:"updatedAt"`
}

func (HardeningStep) TableName() string {
	return "hardening_steps"
}

type HardeningLog struct {
	ID        uint              `gorm:"primaryKey" json:"id"`
	TaskID    uint              `gorm:"index;not null" json:"taskId"`
	StepID    *uint             `gorm:"index" json:"stepId"`
	Level     HardeningLogLevel `gorm:"size:20;not null" json:"level"`
	Message   string            `gorm:"type:text;not null" json:"message"`
	CreatedAt time.Time         `json:"createdAt"`
}

func (HardeningLog) TableName() string {
	return "hardening_logs"
}
```

- [ ] **Step 4: Add models to migration**

Modify `internal/db/db.go`:

```go
func Migrate(database *gorm.DB) error {
	return database.AutoMigrate(
		&model.User{},
		&model.App{},
		&model.Strategy{},
		&model.HardeningTask{},
		&model.HardeningStep{},
		&model.HardeningLog{},
	)
}
```

- [ ] **Step 5: Add DPT config fields and defaults**

Modify `internal/config/config.go`:

```go
type Config struct {
	ServerPort string

	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	JWTSecret      string
	JWTExpireHours int

	MinioEndpoint  string
	MinioAccessKey string
	MinioSecretKey string
	MinioUseSSL    bool
	MinioBucket    string

	MaxUploadSizeMB int64

	DPTJarPath            string
	DPTWorkDir            string
	DPTDefaultVMPRules    string
	DPTTaskTimeoutMinutes int

	AdminEmail    string
	AdminPassword string
}
```

Add defaults inside `Load`:

```go
v.SetDefault("DPT_JAR_PATH", "/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar")
v.SetDefault("DPT_WORK_DIR", "/tmp/beetleshield-hardening")
v.SetDefault("DPT_DEFAULT_VMP_RULES", "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**")
v.SetDefault("DPT_TASK_TIMEOUT_MINUTES", 60)
```

Add fields to the `cfg := &Config{...}` literal:

```go
DPTJarPath:            v.GetString("DPT_JAR_PATH"),
DPTWorkDir:            v.GetString("DPT_WORK_DIR"),
DPTDefaultVMPRules:    v.GetString("DPT_DEFAULT_VMP_RULES"),
DPTTaskTimeoutMinutes: v.GetInt("DPT_TASK_TIMEOUT_MINUTES"),
```

- [ ] **Step 6: Add storage download helper**

Modify `internal/pkg/storage/minio.go` imports to include `os`, then add:

```go
func (s *MinioStorage) GetObjectToFile(ctx context.Context, objectKey string, destinationPath string) error {
	object, err := s.client.GetObject(ctx, s.bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer object.Close()

	dst, err := os.Create(destinationPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, object)
	return err
}
```

- [ ] **Step 7: Add environment example values**

Append to `.env.example`:

```text

DPT_JAR_PATH=/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar
DPT_WORK_DIR=/tmp/beetleshield-hardening
DPT_DEFAULT_VMP_RULES=**
DPT_TASK_TIMEOUT_MINUTES=60
```

- [ ] **Step 8: Run tests**

Run:

```bash
go test ./internal/config ./internal/db ./internal/pkg/storage -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/model/hardening.go internal/db/db.go internal/db/db_test.go internal/config/config.go internal/config/config_test.go internal/pkg/storage/minio.go internal/pkg/storage/minio_test.go .env.example
git commit -m "feat: add hardening models and config"
```

---

### Task 2: Hardening Repository Queue, Step, Log, and History Persistence

**Files:**
- Modify: `internal/repository/app_repository.go`
- Create: `internal/repository/hardening_repository.go`
- Create: `internal/repository/hardening_repository_test.go`

**Interfaces:**
- Consumes models from Task 1.
- Produces:
  - `type HardeningRepository struct`
  - `type HardeningListFilter struct { Status string; AppID uint; Search string; Page int; PageSize int }`
  - `type HardeningLogFilter struct { StepKey model.HardeningStepKey; AfterID uint; Limit int }`
  - `NewHardeningRepository(db *gorm.DB) *HardeningRepository`
  - `CreateTaskWithSteps(task *model.HardeningTask) error`
  - `HasActiveTaskForApp(appID uint) (bool, error)`
  - `NextQueuedTask() (*model.HardeningTask, error)`
  - `MarkTaskRunning(taskID uint, startedAt time.Time) error`
  - `MarkTaskCompleted(taskID uint, unsignedKey string, unsignedSize int64, unsignedSHA string, signedKey string, signedSize int64, signedSHA string, finishedAt time.Time) error`
  - `MarkTaskFailed(taskID uint, summary string, finishedAt time.Time) error`
  - `RecoverRunningTasks(summary string) ([]uint, error)`
  - `List(filter HardeningListFilter) ([]model.HardeningTask, int64, error)`
  - `FindByID(id uint) (*model.HardeningTask, error)`
  - `RecentByApp(appID uint, limit int) ([]model.HardeningTask, error)`
  - `Steps(taskID uint) ([]model.HardeningStep, error)`
  - `FindStep(taskID uint, key model.HardeningStepKey) (*model.HardeningStep, error)`
  - `StartStep(stepID uint, startedAt time.Time) error`
  - `FinishStepSuccess(stepID uint, finishedAt time.Time) error`
  - `FinishStepFailed(stepID uint, message string, finishedAt time.Time) error`
  - `AppendLog(log *model.HardeningLog) error`
  - `Logs(taskID uint, filter HardeningLogFilter) ([]model.HardeningLog, error)`
  - `(*AppRepository).UpdateStatus(id uint, status model.AppStatus) error`

- [ ] **Step 1: Write repository tests**

Create `internal/repository/hardening_repository_test.go` with tests for creation, active-task check, queue ordering, steps/logs, list/search/history, and recovery:

```go
package repository

import (
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
)

func setupHardeningRepo(t *testing.T) (*HardeningRepository, *AppRepository, *gorm.DB) {
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
	cleanupHardeningRepoData(t, database)
	t.Cleanup(func() { cleanupHardeningRepoData(t, database) })
	return NewHardeningRepository(database), NewAppRepository(database), database
}

func cleanupHardeningRepoData(t *testing.T, database *gorm.DB) {
	t.Helper()
	database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-REPO-%')")
	database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-REPO-%')")
	database.Unscoped().Where("task_no LIKE ?", "TASK-REPO-%").Delete(&model.HardeningTask{})
	database.Unscoped().Where("package_name LIKE ?", "com.hardening.repo.%").Delete(&model.App{})
}

func createRepoApp(t *testing.T, appRepo *AppRepository, suffix string) model.App {
	t.Helper()
	app := model.App{
		Name: "Repo App " + suffix,
		PackageName: "com.hardening.repo." + suffix,
		Version: "1.0.0",
		Tag: model.AppTagTool,
		Status: model.AppStatusUnprotected,
		ObjectKey: "repo/" + suffix + "/app.apk",
		MD5: "d41d8cd98f00b204e9800998ecf8427e",
		SHA256: fmt.Sprintf("%064d", len(suffix)+1),
		UploadedBy: 1,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("Create app: %v", err)
	}
	return app
}

func newRepoTask(taskNo string, appID uint, status model.HardeningTaskStatus) model.HardeningTask {
	return model.HardeningTask{
		TaskNo: taskNo,
		AppID: appID,
		Status: status,
		StrategyName: "默认加固模板",
		StrategySnapshot: model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP},
		VMPRulesText: "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		CreatedBy: 1,
	}
}

func TestHardeningRepository_CreateTaskWithStepsAndActiveCheck(t *testing.T) {
	repo, appRepo, _ := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, "active")
	task := newRepoTask("TASK-REPO-ACTIVE", app.ID, model.HardeningTaskStatusQueued)

	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}
	if task.ID == 0 {
		t.Fatal("expected task ID")
	}
	steps, err := repo.Steps(task.ID)
	if err != nil {
		t.Fatalf("Steps() error = %v", err)
	}
	if len(steps) != 6 {
		t.Fatalf("len(steps) = %d, want 6", len(steps))
	}
	if steps[0].StepKey != model.HardeningStepPrepareInput || steps[5].StepKey != model.HardeningStepUploadArtifacts {
		t.Fatalf("unexpected step order: %+v", steps)
	}
	active, err := repo.HasActiveTaskForApp(app.ID)
	if err != nil {
		t.Fatalf("HasActiveTaskForApp() error = %v", err)
	}
	if !active {
		t.Fatal("expected active task")
	}
}

func TestHardeningRepository_QueueStepLogAndCompletion(t *testing.T) {
	repo, appRepo, _ := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, "queue")
	first := newRepoTask("TASK-REPO-QUEUE-1", app.ID, model.HardeningTaskStatusQueued)
	second := newRepoTask("TASK-REPO-QUEUE-2", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&second); err != nil {
		t.Fatalf("Create second: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := repo.CreateTaskWithSteps(&first); err != nil {
		t.Fatalf("Create first: %v", err)
	}

	next, err := repo.NextQueuedTask()
	if err != nil {
		t.Fatalf("NextQueuedTask() error = %v", err)
	}
	if next.TaskNo != "TASK-REPO-QUEUE-2" {
		t.Fatalf("next task = %s, want TASK-REPO-QUEUE-2", next.TaskNo)
	}

	now := time.Now()
	if err := repo.MarkTaskRunning(next.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	step, err := repo.FindStep(next.ID, model.HardeningStepPrepareInput)
	if err != nil {
		t.Fatalf("FindStep() error = %v", err)
	}
	if err := repo.StartStep(step.ID, now); err != nil {
		t.Fatalf("StartStep() error = %v", err)
	}
	if err := repo.AppendLog(&model.HardeningLog{TaskID: next.ID, StepID: &step.ID, Level: model.HardeningLogLevelInfo, Message: "hello"}); err != nil {
		t.Fatalf("AppendLog() error = %v", err)
	}
	if err := repo.FinishStepSuccess(step.ID, now.Add(time.Second)); err != nil {
		t.Fatalf("FinishStepSuccess() error = %v", err)
	}
	if err := repo.MarkTaskCompleted(next.ID, "unsigned.apk", 12, "abc", "signed.apk", 13, "def", now.Add(2*time.Second)); err != nil {
		t.Fatalf("MarkTaskCompleted() error = %v", err)
	}
	logs, err := repo.Logs(next.ID, HardeningLogFilter{AfterID: 0, Limit: 10})
	if err != nil {
		t.Fatalf("Logs() error = %v", err)
	}
	if len(logs) != 1 || logs[0].Message != "hello" {
		t.Fatalf("unexpected logs: %+v", logs)
	}
	found, err := repo.FindByID(next.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.HardeningTaskStatusCompleted || found.UnsignedObjectKey != "unsigned.apk" {
		t.Fatalf("unexpected completed task: %+v", found)
	}
}

func TestHardeningRepository_ListHistoryAndRecoverRunning(t *testing.T) {
	repo, appRepo, _ := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, "history")
	completed := newRepoTask("TASK-REPO-HISTORY-COMPLETED", app.ID, model.HardeningTaskStatusCompleted)
	running := newRepoTask("TASK-REPO-HISTORY-RUNNING", app.ID, model.HardeningTaskStatusRunning)
	if err := repo.CreateTaskWithSteps(&completed); err != nil {
		t.Fatalf("Create completed: %v", err)
	}
	if err := repo.CreateTaskWithSteps(&running); err != nil {
		t.Fatalf("Create running: %v", err)
	}

	items, total, err := repo.List(HardeningListFilter{Search: "Repo App history", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("total=%d len=%d, want 2", total, len(items))
	}
	history, err := repo.RecentByApp(app.ID, 5)
	if err != nil {
		t.Fatalf("RecentByApp() error = %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("len(history) = %d, want 2", len(history))
	}

	ids, err := repo.RecoverRunningTasks("服务重启导致任务中断")
	if err != nil {
		t.Fatalf("RecoverRunningTasks() error = %v", err)
	}
	if len(ids) != 1 || ids[0] != running.ID {
		t.Fatalf("recovered ids = %+v, want [%d]", ids, running.ID)
	}
	recovered, err := repo.FindByID(running.ID)
	if err != nil {
		t.Fatalf("FindByID() recovered error = %v", err)
	}
	if recovered.Status != model.HardeningTaskStatusFailed || recovered.ErrorSummary != "服务重启导致任务中断" {
		t.Fatalf("unexpected recovered task: %+v", recovered)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/repository -run HardeningRepository -v
```

Expected: FAIL because `HardeningRepository` and `UpdateStatus` are not defined.

- [ ] **Step 3: Add app status update**

Append to `internal/repository/app_repository.go`:

```go
func (r *AppRepository) UpdateStatus(id uint, status model.AppStatus) error {
	return r.db.Model(&model.App{}).Where("id = ?", id).Update("status", status).Error
}
```

- [ ] **Step 4: Implement hardening repository**

Create `internal/repository/hardening_repository.go`:

```go
package repository

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type HardeningListFilter struct {
	Status string
	AppID uint
	Search string
	Page int
	PageSize int
}

type HardeningLogFilter struct {
	StepKey model.HardeningStepKey
	AfterID uint
	Limit int
}

type HardeningRepository struct {
	db *gorm.DB
}

func NewHardeningRepository(db *gorm.DB) *HardeningRepository {
	return &HardeningRepository{db: db}
}

var defaultHardeningSteps = []model.HardeningStep{
	{StepKey: model.HardeningStepPrepareInput, Name: "准备输入", SortOrder: 1, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepParsePackage, Name: "解析包体", SortOrder: 2, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepApplyStrategy, Name: "应用策略", SortOrder: 3, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepRunEngine, Name: "执行加固", SortOrder: 4, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepCollectArtifacts, Name: "收集产物", SortOrder: 5, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepUploadArtifacts, Name: "上传产物", SortOrder: 6, Status: model.HardeningStepStatusWaiting},
}

func (r *HardeningRepository) CreateTaskWithSteps(task *model.HardeningTask) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(task).Error; err != nil {
			return err
		}
		for _, step := range defaultHardeningSteps {
			step.TaskID = task.ID
			if err := tx.Create(&step).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *HardeningRepository) HasActiveTaskForApp(appID uint) (bool, error) {
	var count int64
	err := r.db.Model(&model.HardeningTask{}).
		Where("app_id = ? AND status IN ?", appID, []model.HardeningTaskStatus{
			model.HardeningTaskStatusQueued,
			model.HardeningTaskStatusRunning,
		}).
		Count(&count).Error
	return count > 0, err
}

func (r *HardeningRepository) NextQueuedTask() (*model.HardeningTask, error) {
	var task model.HardeningTask
	err := r.db.Preload("App").
		Where("status = ?", model.HardeningTaskStatusQueued).
		Order("created_at ASC, id ASC").
		First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *HardeningRepository) MarkTaskRunning(taskID uint, startedAt time.Time) error {
	return r.db.Model(&model.HardeningTask{}).
		Where("id = ?", taskID).
		Updates(map[string]interface{}{"status": model.HardeningTaskStatusRunning, "started_at": startedAt}).Error
}

func (r *HardeningRepository) MarkTaskCompleted(taskID uint, unsignedKey string, unsignedSize int64, unsignedSHA string, signedKey string, signedSize int64, signedSHA string, finishedAt time.Time) error {
	return r.db.Model(&model.HardeningTask{}).
		Where("id = ?", taskID).
		Updates(map[string]interface{}{
			"status": model.HardeningTaskStatusCompleted,
			"unsigned_object_key": unsignedKey,
			"unsigned_file_size": unsignedSize,
			"unsigned_sha256": unsignedSHA,
			"signed_test_object_key": signedKey,
			"signed_test_file_size": signedSize,
			"signed_test_sha256": signedSHA,
			"finished_at": finishedAt,
			"error_summary": "",
		}).Error
}

func (r *HardeningRepository) MarkTaskFailed(taskID uint, summary string, finishedAt time.Time) error {
	return r.db.Model(&model.HardeningTask{}).
		Where("id = ?", taskID).
		Updates(map[string]interface{}{"status": model.HardeningTaskStatusFailed, "error_summary": summary, "finished_at": finishedAt}).Error
}

func (r *HardeningRepository) RecoverRunningTasks(summary string) ([]uint, error) {
	var tasks []model.HardeningTask
	if err := r.db.Where("status = ?", model.HardeningTaskStatusRunning).Find(&tasks).Error; err != nil {
		return nil, err
	}
	now := time.Now()
	ids := make([]uint, 0, len(tasks))
	for _, task := range tasks {
		ids = append(ids, task.ID)
	}
	if len(ids) == 0 {
		return ids, nil
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.HardeningTask{}).Where("id IN ?", ids).Updates(map[string]interface{}{"status": model.HardeningTaskStatusFailed, "error_summary": summary, "finished_at": now}).Error; err != nil {
			return err
		}
		return tx.Model(&model.HardeningStep{}).Where("task_id IN ? AND status = ?", ids, model.HardeningStepStatusRunning).Updates(map[string]interface{}{"status": model.HardeningStepStatusFailed, "error_message": summary, "finished_at": now}).Error
	})
	return ids, err
}

func (r *HardeningRepository) List(filter HardeningListFilter) ([]model.HardeningTask, int64, error) {
	query := r.db.Model(&model.HardeningTask{}).Joins("LEFT JOIN apps ON apps.id = hardening_tasks.app_id")
	if filter.Status != "" {
		query = query.Where("hardening_tasks.status = ?", filter.Status)
	}
	if filter.AppID != 0 {
		query = query.Where("hardening_tasks.app_id = ?", filter.AppID)
	}
	if filter.Search != "" {
		like := "%" + filter.Search + "%"
		query = query.Where("hardening_tasks.task_no ILIKE ? OR apps.name ILIKE ? OR apps.package_name ILIKE ?", like, like, like)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 10
	}
	var tasks []model.HardeningTask
	err := query.Preload("App").
		Order("hardening_tasks.created_at DESC, hardening_tasks.id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&tasks).Error
	return tasks, total, err
}

func (r *HardeningRepository) FindByID(id uint) (*model.HardeningTask, error) {
	var task model.HardeningTask
	if err := r.db.Preload("App").First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *HardeningRepository) RecentByApp(appID uint, limit int) ([]model.HardeningTask, error) {
	if limit < 1 {
		limit = 5
	}
	var tasks []model.HardeningTask
	err := r.db.Preload("App").Where("app_id = ?", appID).Order("created_at DESC, id DESC").Limit(limit).Find(&tasks).Error
	return tasks, err
}

func (r *HardeningRepository) Steps(taskID uint) ([]model.HardeningStep, error) {
	var steps []model.HardeningStep
	err := r.db.Where("task_id = ?", taskID).Order("sort_order ASC").Find(&steps).Error
	return steps, err
}

func (r *HardeningRepository) FindStep(taskID uint, key model.HardeningStepKey) (*model.HardeningStep, error) {
	var step model.HardeningStep
	err := r.db.Where("task_id = ? AND step_key = ?", taskID, key).First(&step).Error
	if err != nil {
		return nil, err
	}
	return &step, nil
}

func (r *HardeningRepository) StartStep(stepID uint, startedAt time.Time) error {
	return r.db.Model(&model.HardeningStep{}).Where("id = ?", stepID).Updates(map[string]interface{}{"status": model.HardeningStepStatusRunning, "started_at": startedAt}).Error
}

func (r *HardeningRepository) FinishStepSuccess(stepID uint, finishedAt time.Time) error {
	return r.db.Model(&model.HardeningStep{}).Where("id = ?", stepID).Updates(map[string]interface{}{"status": model.HardeningStepStatusSuccess, "finished_at": finishedAt, "error_message": ""}).Error
}

func (r *HardeningRepository) FinishStepFailed(stepID uint, message string, finishedAt time.Time) error {
	return r.db.Model(&model.HardeningStep{}).Where("id = ?", stepID).Updates(map[string]interface{}{"status": model.HardeningStepStatusFailed, "finished_at": finishedAt, "error_message": message}).Error
}

func (r *HardeningRepository) AppendLog(log *model.HardeningLog) error {
	return r.db.Create(log).Error
}

func (r *HardeningRepository) Logs(taskID uint, filter HardeningLogFilter) ([]model.HardeningLog, error) {
	query := r.db.Model(&model.HardeningLog{}).Where("hardening_logs.task_id = ?", taskID)
	if filter.AfterID != 0 {
		query = query.Where("hardening_logs.id > ?", filter.AfterID)
	}
	if filter.StepKey != "" {
		query = query.Joins("JOIN hardening_steps ON hardening_steps.id = hardening_logs.step_id").Where("hardening_steps.step_key = ?", filter.StepKey)
	}
	limit := filter.Limit
	if limit < 1 || limit > 500 {
		limit = 200
	}
	var logs []model.HardeningLog
	err := query.Order("hardening_logs.id ASC").Limit(limit).Find(&logs).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return []model.HardeningLog{}, nil
	}
	return logs, err
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
go test ./internal/repository -run 'HardeningRepository|AppRepository' -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/repository/app_repository.go internal/repository/hardening_repository.go internal/repository/hardening_repository_test.go
git commit -m "feat: add hardening repository queue"
```

---

### Task 3: Command Builder, Default Rules, and Artifact Helpers

**Files:**
- Create: `internal/service/hardening_command.go`
- Create: `internal/service/hardening_command_test.go`

**Interfaces:**
- Produces:
  - `const DefaultStrategyName = "默认加固模板"`
  - `func NormalizeVMPRules(input string, fallback string) string`
  - `type EngineCommandInput struct { JavaBin string; JarPath string; InputPath string; OutputPath string; RulesPath string; Strategy model.Strategy; EnableFileIntegrityCheck bool; EnableProxyDetect bool }`
  - `func BuildDPTCommand(input EngineCommandInput) []string`
  - `type ArtifactInfo struct { Path string; ObjectKey string; Size int64; SHA256 string }`
  - `func SHA256File(path string) (string, int64, error)`
  - `func SignedTestArtifactPath(outputPath string) string`
- These helpers are consumed by `HardeningService` and `HardeningWorker`.

- [ ] **Step 1: Write failing command tests**

Create `internal/service/hardening_command_test.go`:

```go
package service

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"beetleshield-backend/internal/model"
)

func TestNormalizeVMPRules_DefaultAndCustom(t *testing.T) {
	fallback := "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**"
	if got := NormalizeVMPRules("", fallback); got != fallback {
		t.Fatalf("empty rules = %q, want fallback", got)
	}
	custom := "com.example.**\n!com.example.Skip"
	if got := NormalizeVMPRules("  "+custom+"  ", fallback); got != custom {
		t.Fatalf("custom rules = %q, want %q", got, custom)
	}
}

func TestBuildDPTCommand_HighStrengthMapping(t *testing.T) {
	args := BuildDPTCommand(EngineCommandInput{
		JavaBin: "java",
		JarPath: "/opt/dpt.jar",
		InputPath: "/work/input.apk",
		OutputPath: "/work/output.apk",
		RulesPath: "/work/vmp-rules.txt",
		Strategy: model.Strategy{
			Frida: true,
			Xposed: true,
			Emulator: true,
			DexLevel: model.DexLevelHigh,
			StringEncrypt: true,
			SoShell: model.SoShellVMP,
			RootDetect: true,
			Signature: true,
			AntiHook: true,
			ResEncrypt: true,
		},
		EnableFileIntegrityCheck: true,
		EnableProxyDetect: true,
	})
	want := []string{
		"java", "-jar", "/opt/dpt.jar",
		"-f", "/work/input.apk",
		"-o", "/work/output.apk",
		"--no-sign",
		"--enable-emulator-detect",
		"--enable-root-detect",
		"--enable-apk-sig-verify", "--apk-sig-policy", "block",
		"--enable-hook-detect",
		"--enable-string-encrypt",
		"--enable-assets-encrypt",
		"--enable-vmp", "--vmp-rules", "/work/vmp-rules.txt",
		"--enable-file-integrity-check",
		"--enable-proxy-detect",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v\nwant %#v", args, want)
	}
}

func TestBuildDPTCommand_DeduplicatesHookAndVMP(t *testing.T) {
	args := BuildDPTCommand(EngineCommandInput{
		JavaBin: "java",
		JarPath: "/opt/dpt.jar",
		InputPath: "/work/input.apk",
		OutputPath: "/work/output.apk",
		RulesPath: "/work/vmp-rules.txt",
		Strategy: model.Strategy{
			Frida: true,
			Xposed: true,
			AntiHook: true,
			DexLevel: model.DexLevelHigh,
			SoShell: model.SoShellVMP,
		},
	})
	if countArg(args, "--enable-hook-detect") != 1 {
		t.Fatalf("hook flag count = %d, want 1 in %#v", countArg(args, "--enable-hook-detect"), args)
	}
	if countArg(args, "--enable-vmp") != 1 {
		t.Fatalf("vmp flag count = %d, want 1 in %#v", countArg(args, "--enable-vmp"), args)
	}
}

func TestSHA256FileAndSignedTestArtifactPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.apk")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	sum, size, err := SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File() error = %v", err)
	}
	if size != 3 {
		t.Fatalf("size = %d, want 3", size)
	}
	if sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256 = %q", sum)
	}
	if got := SignedTestArtifactPath(path); got != filepath.Join(filepath.Dir(path), "output_signed.apk") {
		t.Fatalf("SignedTestArtifactPath() = %q", got)
	}
}

func countArg(args []string, target string) int {
	count := 0
	for _, arg := range args {
		if arg == target {
			count++
		}
	}
	return count
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/service -run 'NormalizeVMPRules|BuildDPTCommand|SHA256File' -v
```

Expected: FAIL because helpers do not exist.

- [ ] **Step 3: Implement command helpers**

Create `internal/service/hardening_command.go`:

```go
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"beetleshield-backend/internal/model"
)

const DefaultStrategyName = "默认加固模板"

type EngineCommandInput struct {
	JavaBin string
	JarPath string
	InputPath string
	OutputPath string
	RulesPath string
	Strategy model.Strategy
	EnableFileIntegrityCheck bool
	EnableProxyDetect bool
}

type ArtifactInfo struct {
	Path string
	ObjectKey string
	Size int64
	SHA256 string
}

func NormalizeVMPRules(input string, fallback string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func BuildDPTCommand(input EngineCommandInput) []string {
	javaBin := input.JavaBin
	if javaBin == "" {
		javaBin = "java"
	}
	args := []string{
		javaBin, "-jar", input.JarPath,
		"-f", input.InputPath,
		"-o", input.OutputPath,
		"--no-sign",
	}
	if input.Strategy.Emulator {
		args = append(args, "--enable-emulator-detect")
	}
	if input.Strategy.RootDetect {
		args = append(args, "--enable-root-detect")
	}
	if input.Strategy.Signature {
		args = append(args, "--enable-apk-sig-verify", "--apk-sig-policy", "block")
	}
	if input.Strategy.AntiHook || input.Strategy.Frida || input.Strategy.Xposed {
		args = append(args, "--enable-hook-detect")
	}
	if input.Strategy.StringEncrypt {
		args = append(args, "--enable-string-encrypt")
	}
	if input.Strategy.ResEncrypt {
		args = append(args, "--enable-assets-encrypt")
	}
	if input.Strategy.DexLevel == model.DexLevelHigh || input.Strategy.SoShell == model.SoShellVMP {
		args = append(args, "--enable-vmp", "--vmp-rules", input.RulesPath)
	}
	if input.EnableFileIntegrityCheck {
		args = append(args, "--enable-file-integrity-check")
	}
	if input.EnableProxyDetect {
		args = append(args, "--enable-proxy-detect")
	}
	return args
}

func SHA256File(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func SignedTestArtifactPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	if ext == "" {
		return outputPath + "_signed"
	}
	return strings.TrimSuffix(outputPath, ext) + "_signed" + ext
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
go test ./internal/service -run 'NormalizeVMPRules|BuildDPTCommand|SHA256File' -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/service/hardening_command.go internal/service/hardening_command_test.go
git commit -m "feat: add hardening command builder"
```

---

### Task 4: Hardening Service Create, Read, Logs, History, and Download URLs

**Files:**
- Create: `internal/service/hardening_service.go`
- Create: `internal/service/hardening_service_test.go`

**Interfaces:**
- Consumes Task 2 repository and Task 3 helpers.
- Produces:
  - Errors: `ErrHardeningAppNotFound`, `ErrHardeningTaskNotFound`, `ErrHardeningActiveTaskExists`, `ErrHardeningArtifactNotFound`, `ErrInvalidHardeningArtifact`
  - `type CreateHardeningTaskInput struct { AppID uint; StrategyName string; StrategySnapshot *model.Strategy; VMPRulesText string; EnableFileIntegrityCheck bool; EnableProxyDetect bool; CreatedBy uint }`
  - `type HardeningTaskDetail struct { Task model.HardeningTask; Steps []model.HardeningStep; RecentLogs []model.HardeningLog }`
  - `NewHardeningService(hardeningRepo *repository.HardeningRepository, appRepo *repository.AppRepository, strategyService *StrategyService, storage DownloadURLProvider, defaultVMPRules string) *HardeningService`
  - `Create(ctx context.Context, input CreateHardeningTaskInput) (*HardeningTaskDetail, error)`
  - `List(filter repository.HardeningListFilter) ([]model.HardeningTask, int64, error)`
  - `Get(id uint) (*HardeningTaskDetail, error)`
  - `Logs(taskID uint, filter repository.HardeningLogFilter) ([]model.HardeningLog, error)`
  - `History(appID uint) ([]model.HardeningTask, error)`
  - `DownloadURL(ctx context.Context, taskID uint, artifact string) (string, error)`
  - `type DownloadURLProvider interface { PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error) }`

- [ ] **Step 1: Write service tests**

Create `internal/service/hardening_service_test.go`:

```go
package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type fakeHardeningURLStorage struct {
	urls map[string]string
}

func (f fakeHardeningURLStorage) PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error) {
	if f.urls == nil {
		return "https://minio.example/" + objectKey, nil
	}
	return f.urls[objectKey], nil
}

func setupHardeningServiceTest(t *testing.T) (*service.HardeningService, *repository.AppRepository, *repository.HardeningRepository) {
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
	database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
	database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
	database.Exec("DELETE FROM hardening_tasks WHERE app_id IN (SELECT id FROM apps WHERE package_name LIKE 'com.hardening.service.%')")
	database.Unscoped().Where("package_name LIKE ?", "com.hardening.service.%").Delete(&model.App{})
	t.Cleanup(func() {
		database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
		database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
		database.Exec("DELETE FROM hardening_tasks WHERE app_id IN (SELECT id FROM apps WHERE package_name LIKE 'com.hardening.service.%')")
		database.Unscoped().Where("package_name LIKE ?", "com.hardening.service.%").Delete(&model.App{})
		database.Unscoped().Where("updated_by = ?", uint(515151)).Delete(&model.Strategy{})
	})

	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)
	strategyRepo := repository.NewStrategyRepository(database)
	strategySvc := service.NewStrategyService(strategyRepo)
	svc := service.NewHardeningService(hardeningRepo, appRepo, strategySvc, fakeHardeningURLStorage{}, "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**")
	return svc, appRepo, hardeningRepo
}

func createHardeningServiceApp(t *testing.T, appRepo *repository.AppRepository, suffix string) model.App {
	t.Helper()
	app := model.App{
		Name: "Service App " + suffix,
		PackageName: "com.hardening.service." + suffix,
		Version: "1.0.0",
		Tag: model.AppTagTool,
		Status: model.AppStatusUnprotected,
		ObjectKey: "service/" + suffix + "/app.apk",
		MD5: "d41d8cd98f00b204e9800998ecf8427e",
		SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		UploadedBy: 1,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("create app: %v", err)
	}
	return app
}

func TestHardeningService_CreateDefaultsAndSetsAppProcessing(t *testing.T) {
	svc, appRepo, _ := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, "create")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{
		AppID: app.ID,
		CreatedBy: 42,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if detail.Task.Status != model.HardeningTaskStatusQueued {
		t.Fatalf("status = %s", detail.Task.Status)
	}
	if detail.Task.StrategyName != service.DefaultStrategyName {
		t.Fatalf("strategy name = %q", detail.Task.StrategyName)
	}
	if !strings.Contains(detail.Task.VMPRulesText, "**") {
		t.Fatalf("rules text = %q", detail.Task.VMPRulesText)
	}
	if len(detail.Steps) != 6 {
		t.Fatalf("len(steps) = %d, want 6", len(detail.Steps))
	}
	found, err := appRepo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.AppStatusProcessing {
		t.Fatalf("app status = %s, want processing", found.Status)
	}
}

func TestHardeningService_CreateRejectsActiveTask(t *testing.T) {
	svc, appRepo, _ := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, "active")
	_, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 42})
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	_, err = svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 42})
	if err != service.ErrHardeningActiveTaskExists {
		t.Fatalf("second err = %v, want ErrHardeningActiveTaskExists", err)
	}
}

func TestHardeningService_CreateUsesCustomSnapshotAndRules(t *testing.T) {
	svc, appRepo, _ := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, "custom")
	strategy := model.Strategy{DexLevel: model.DexLevelLow, SoShell: model.SoShellNone, RootDetect: true}
	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{
		AppID: app.ID,
		StrategyName: "信息院 App 加固模板",
		StrategySnapshot: &strategy,
		VMPRulesText: "com.example.**",
		EnableFileIntegrityCheck: true,
		EnableProxyDetect: true,
		CreatedBy: 7,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if detail.Task.StrategyName != "信息院 App 加固模板" {
		t.Fatalf("strategy name = %q", detail.Task.StrategyName)
	}
	if detail.Task.StrategySnapshot.DexLevel != model.DexLevelLow || !detail.Task.StrategySnapshot.RootDetect {
		t.Fatalf("strategy snapshot = %+v", detail.Task.StrategySnapshot)
	}
	if detail.Task.VMPRulesText != "com.example.**" {
		t.Fatalf("rules = %q", detail.Task.VMPRulesText)
	}
	if !detail.Task.EnableFileIntegrityCheck || !detail.Task.EnableProxyDetect {
		t.Fatalf("advanced flags not preserved: %+v", detail.Task)
	}
}

func TestHardeningService_DownloadURLArtifacts(t *testing.T) {
	svc, appRepo, repo := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, "download")
	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	now := time.Now()
	if err := repo.MarkTaskCompleted(detail.Task.ID, "hardening/unsigned.apk", 10, "abc", "hardening/signed.apk", 11, "def", now); err != nil {
		t.Fatalf("MarkTaskCompleted() error = %v", err)
	}
	unsignedURL, err := svc.DownloadURL(context.Background(), detail.Task.ID, "")
	if err != nil {
		t.Fatalf("DownloadURL(unsigned) error = %v", err)
	}
	if !strings.Contains(unsignedURL, "hardening/unsigned.apk") {
		t.Fatalf("unsigned URL = %q", unsignedURL)
	}
	signedURL, err := svc.DownloadURL(context.Background(), detail.Task.ID, "signed_test")
	if err != nil {
		t.Fatalf("DownloadURL(signed_test) error = %v", err)
	}
	if !strings.Contains(signedURL, "hardening/signed.apk") {
		t.Fatalf("signed URL = %q", signedURL)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/service -run HardeningService -v
```

Expected: FAIL because `HardeningService` is not defined.

- [ ] **Step 3: Implement hardening service**

Create `internal/service/hardening_service.go`:

```go
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

var (
	ErrHardeningAppNotFound = errors.New("app not found")
	ErrHardeningTaskNotFound = errors.New("hardening task not found")
	ErrHardeningActiveTaskExists = errors.New("app already has an active hardening task")
	ErrHardeningArtifactNotFound = errors.New("hardening artifact not found")
	ErrInvalidHardeningArtifact = errors.New("invalid hardening artifact")
)

type DownloadURLProvider interface {
	PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error)
}

type CreateHardeningTaskInput struct {
	AppID uint
	StrategyName string
	StrategySnapshot *model.Strategy
	VMPRulesText string
	EnableFileIntegrityCheck bool
	EnableProxyDetect bool
	CreatedBy uint
}

type HardeningTaskDetail struct {
	Task model.HardeningTask `json:"task"`
	Steps []model.HardeningStep `json:"steps"`
	RecentLogs []model.HardeningLog `json:"recentLogs"`
}

type HardeningService struct {
	hardeningRepo *repository.HardeningRepository
	appRepo *repository.AppRepository
	strategyService *StrategyService
	storage DownloadURLProvider
	defaultVMPRules string
}

func NewHardeningService(hardeningRepo *repository.HardeningRepository, appRepo *repository.AppRepository, strategyService *StrategyService, storage DownloadURLProvider, defaultVMPRules string) *HardeningService {
	return &HardeningService{hardeningRepo: hardeningRepo, appRepo: appRepo, strategyService: strategyService, storage: storage, defaultVMPRules: defaultVMPRules}
}

func (s *HardeningService) Create(ctx context.Context, input CreateHardeningTaskInput) (*HardeningTaskDetail, error) {
	app, err := s.appRepo.FindByID(input.AppID)
	if err != nil {
		return nil, ErrHardeningAppNotFound
	}
	active, err := s.hardeningRepo.HasActiveTaskForApp(app.ID)
	if err != nil {
		return nil, err
	}
	if active {
		return nil, ErrHardeningActiveTaskExists
	}

	strategy := model.Strategy{}
	if input.StrategySnapshot != nil {
		strategy = *input.StrategySnapshot
	} else {
		current, err := s.strategyService.GetCurrent()
		if err != nil {
			return nil, err
		}
		strategy = *current
	}
	strategyName := input.StrategyName
	if strategyName == "" {
		strategyName = DefaultStrategyName
	}

	task := &model.HardeningTask{
		TaskNo: generateHardeningTaskNo(time.Now()),
		AppID: app.ID,
		Status: model.HardeningTaskStatusQueued,
		StrategyName: strategyName,
		StrategySnapshot: strategy,
		VMPRulesText: NormalizeVMPRules(input.VMPRulesText, s.defaultVMPRules),
		EnableFileIntegrityCheck: input.EnableFileIntegrityCheck,
		EnableProxyDetect: input.EnableProxyDetect,
		CreatedBy: input.CreatedBy,
	}
	if err := s.hardeningRepo.CreateTaskWithSteps(task); err != nil {
		return nil, err
	}
	if err := s.appRepo.UpdateStatus(app.ID, model.AppStatusProcessing); err != nil {
		return nil, err
	}
	return s.Get(task.ID)
}

func (s *HardeningService) List(filter repository.HardeningListFilter) ([]model.HardeningTask, int64, error) {
	return s.hardeningRepo.List(filter)
}

func (s *HardeningService) Get(id uint) (*HardeningTaskDetail, error) {
	task, err := s.hardeningRepo.FindByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningTaskNotFound
		}
		return nil, err
	}
	steps, err := s.hardeningRepo.Steps(id)
	if err != nil {
		return nil, err
	}
	logs, err := s.hardeningRepo.Logs(id, repository.HardeningLogFilter{Limit: 20})
	if err != nil {
		return nil, err
	}
	return &HardeningTaskDetail{Task: *task, Steps: steps, RecentLogs: logs}, nil
}

func (s *HardeningService) Logs(taskID uint, filter repository.HardeningLogFilter) ([]model.HardeningLog, error) {
	if _, err := s.hardeningRepo.FindByID(taskID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningTaskNotFound
		}
		return nil, err
	}
	return s.hardeningRepo.Logs(taskID, filter)
}

func (s *HardeningService) History(appID uint) ([]model.HardeningTask, error) {
	if _, err := s.appRepo.FindByID(appID); err != nil {
		return nil, ErrHardeningAppNotFound
	}
	return s.hardeningRepo.RecentByApp(appID, 5)
}

func (s *HardeningService) DownloadURL(ctx context.Context, taskID uint, artifact string) (string, error) {
	task, err := s.hardeningRepo.FindByID(taskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrHardeningTaskNotFound
		}
		return "", err
	}
	objectKey := task.UnsignedObjectKey
	if artifact == "" || artifact == "unsigned" {
		objectKey = task.UnsignedObjectKey
	} else if artifact == "signed_test" {
		objectKey = task.SignedTestObjectKey
	} else {
		return "", ErrInvalidHardeningArtifact
	}
	if objectKey == "" {
		return "", ErrHardeningArtifactNotFound
	}
	return s.storage.PresignedDownloadURL(ctx, objectKey, 15*time.Minute)
}

func generateHardeningTaskNo(now time.Time) string {
	return fmt.Sprintf("TASK-%s-%d", now.Format("20060102"), now.UnixNano())
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
go test ./internal/service -run 'HardeningService|NormalizeVMPRules|BuildDPTCommand|SHA256File' -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/service/hardening_service.go internal/service/hardening_service_test.go
git commit -m "feat: add hardening service"
```

---

### Task 5: Engine Runner and Serial Worker

**Files:**
- Create: `internal/worker/engine.go`
- Create: `internal/worker/hardening_worker.go`
- Create: `internal/worker/hardening_worker_test.go`

**Interfaces:**
- Consumes Task 2 repository, Task 3 command helpers, Task 4 service concepts.
- Produces:
  - `type EngineRunRequest struct { Command []string; WorkDir string }`
  - `type EngineRunner interface { Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error }`
  - `type DPTRunner struct{}`
  - `func (DPTRunner) Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error`
  - `type ObjectStorage interface { GetObjectToFile(ctx context.Context, objectKey string, destinationPath string) error; PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string) error }`
  - `type HardeningWorkerConfig struct { JarPath string; WorkDir string; DefaultVMPRules string; Timeout time.Duration }`
  - `NewHardeningWorker(repo *repository.HardeningRepository, appRepo *repository.AppRepository, storage ObjectStorage, runner EngineRunner, cfg HardeningWorkerConfig) *HardeningWorker`
  - `func (w *HardeningWorker) RecoverRunning(ctx context.Context) error`
  - `func (w *HardeningWorker) ProcessNext(ctx context.Context) (bool, error)`
  - `func (w *HardeningWorker) Start(ctx context.Context, interval time.Duration)`

- [ ] **Step 1: Write worker tests with fakes**

Create `internal/worker/hardening_worker_test.go`:

```go
package worker

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type fakeWorkerStorage struct {
	objects map[string][]byte
}

func (s *fakeWorkerStorage) GetObjectToFile(ctx context.Context, objectKey string, destinationPath string) error {
	data := s.objects[objectKey]
	return os.WriteFile(destinationPath, data, 0600)
}

func (s *fakeWorkerStorage) PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string) error {
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}
	s.objects[objectKey] = buf.Bytes()
	return nil
}

type fakeEngineRunner struct {
	writeUnsigned bool
	writeSigned bool
	err error
	lines []string
	lastCommand []string
}

func (r *fakeEngineRunner) Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error {
	r.lastCommand = append([]string{}, req.Command...)
	for _, line := range r.lines {
		onLine(model.HardeningLogLevelInfo, line)
	}
	output := commandValue(req.Command, "-o")
	if r.writeUnsigned {
		if err := os.WriteFile(output, []byte("unsigned"), 0600); err != nil {
			return err
		}
	}
	if r.writeSigned {
		if err := os.WriteFile(strings.TrimSuffix(output, filepath.Ext(output))+"_signed"+filepath.Ext(output), []byte("signed"), 0600); err != nil {
			return err
		}
	}
	return r.err
}

func commandValue(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func setupWorkerTest(t *testing.T) (*HardeningWorker, *repository.HardeningRepository, *repository.AppRepository, *fakeWorkerStorage, *fakeEngineRunner) {
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
	database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-WORKER-%')")
	database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-WORKER-%')")
	database.Exec("DELETE FROM hardening_tasks WHERE task_no LIKE 'TASK-WORKER-%'")
	database.Unscoped().Where("package_name LIKE ?", "com.hardening.worker.%").Delete(&model.App{})
	t.Cleanup(func() {
		database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-WORKER-%')")
		database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-WORKER-%')")
		database.Exec("DELETE FROM hardening_tasks WHERE task_no LIKE 'TASK-WORKER-%'")
		database.Unscoped().Where("package_name LIKE ?", "com.hardening.worker.%").Delete(&model.App{})
	})
	appRepo := repository.NewAppRepository(database)
	repo := repository.NewHardeningRepository(database)
	storage := &fakeWorkerStorage{objects: map[string][]byte{}}
	runner := &fakeEngineRunner{writeUnsigned: true, writeSigned: true, lines: []string{"engine started", "All done."}}
	w := NewHardeningWorker(repo, appRepo, storage, runner, HardeningWorkerConfig{
		JarPath: "/opt/dpt.jar",
		WorkDir: t.TempDir(),
		DefaultVMPRules: "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		Timeout: time.Minute,
	})
	return w, repo, appRepo, storage, runner
}

func createWorkerTask(t *testing.T, repo *repository.HardeningRepository, appRepo *repository.AppRepository, storage *fakeWorkerStorage, suffix string) model.HardeningTask {
	t.Helper()
	app := model.App{
		Name: "Worker App " + suffix,
		PackageName: "com.hardening.worker." + suffix,
		Version: "1.0.0",
		Tag: model.AppTagTool,
		Status: model.AppStatusProcessing,
		ObjectKey: "worker/" + suffix + "/input.apk",
		MD5: "d41d8cd98f00b204e9800998ecf8427e",
		SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		UploadedBy: 1,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("create app: %v", err)
	}
	storage.objects[app.ObjectKey] = []byte("input apk")
	task := model.HardeningTask{
		TaskNo: "TASK-WORKER-" + strings.ToUpper(suffix),
		AppID: app.ID,
		Status: model.HardeningTaskStatusQueued,
		StrategyName: "默认加固模板",
		StrategySnapshot: model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, RootDetect: true, Signature: true},
		VMPRulesText: "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		EnableFileIntegrityCheck: true,
		EnableProxyDetect: true,
		CreatedBy: 1,
	}
	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}
	return task
}

func TestHardeningWorker_ProcessNextSuccessUploadsArtifacts(t *testing.T) {
	w, repo, appRepo, storage, runner := setupWorkerTest(t)
	task := createWorkerTask(t, repo, appRepo, storage, "success")

	processed, err := w.ProcessNext(context.Background())
	if err != nil {
		t.Fatalf("ProcessNext() error = %v", err)
	}
	if !processed {
		t.Fatal("processed = false, want true")
	}
	found, err := repo.FindByID(task.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.HardeningTaskStatusCompleted {
		t.Fatalf("task status = %s", found.Status)
	}
	if found.UnsignedObjectKey == "" || found.SignedTestObjectKey == "" {
		t.Fatalf("artifact keys missing: %+v", found)
	}
	if _, ok := storage.objects[found.UnsignedObjectKey]; !ok {
		t.Fatalf("unsigned object not uploaded: %s", found.UnsignedObjectKey)
	}
	if countString(runner.lastCommand, "--vmp-rules") != 1 || countString(runner.lastCommand, "--enable-file-integrity-check") != 1 {
		t.Fatalf("unexpected command: %#v", runner.lastCommand)
	}
	app, _ := appRepo.FindByID(found.AppID)
	if app.Status != model.AppStatusCompleted {
		t.Fatalf("app status = %s", app.Status)
	}
	steps, _ := repo.Steps(task.ID)
	for _, step := range steps {
		if step.Status != model.HardeningStepStatusSuccess {
			t.Fatalf("step %s status = %s", step.StepKey, step.Status)
		}
	}
}

func TestHardeningWorker_ProcessNextNoUnsignedFails(t *testing.T) {
	w, repo, appRepo, storage, runner := setupWorkerTest(t)
	runner.writeUnsigned = false
	runner.writeSigned = true
	task := createWorkerTask(t, repo, appRepo, storage, "fail")

	processed, err := w.ProcessNext(context.Background())
	if err != nil {
		t.Fatalf("ProcessNext() error = %v", err)
	}
	if !processed {
		t.Fatal("processed = false, want true")
	}
	found, _ := repo.FindByID(task.ID)
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed", found.Status)
	}
	app, _ := appRepo.FindByID(found.AppID)
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}
}

func TestHardeningWorker_RecoverRunningMarksTasksAndAppsFailed(t *testing.T) {
	w, repo, appRepo, storage, _ := setupWorkerTest(t)
	task := createWorkerTask(t, repo, appRepo, storage, "recover")
	if err := repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := w.RecoverRunning(context.Background()); err != nil {
		t.Fatalf("RecoverRunning() error = %v", err)
	}
	found, _ := repo.FindByID(task.ID)
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s", found.Status)
	}
	app, _ := appRepo.FindByID(found.AppID)
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s", app.Status)
	}
}

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/worker -v
```

Expected: FAIL because worker package does not exist.

- [ ] **Step 3: Implement engine runner**

Create `internal/worker/engine.go`:

```go
package worker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"beetleshield-backend/internal/model"
)

type EngineRunRequest struct {
	Command []string
	WorkDir string
}

type EngineRunner interface {
	Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error
}

type DPTRunner struct{}

func (DPTRunner) Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error {
	if len(req.Command) == 0 {
		return fmt.Errorf("empty engine command")
	}
	cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
	cmd.Dir = req.WorkDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go scanEngineLines(stdout, model.HardeningLogLevelInfo, onLine, &wg)
	go scanEngineLines(stderr, model.HardeningLogLevelError, onLine, &wg)
	waitErr := cmd.Wait()
	wg.Wait()
	return waitErr
}

func scanEngineLines(reader io.Reader, fallback model.HardeningLogLevel, onLine func(model.HardeningLogLevel, string), wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		onLine(classifyEngineLine(line, fallback), line)
	}
}

func classifyEngineLine(line string, fallback model.HardeningLogLevel) model.HardeningLogLevel {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "ERROR") || strings.Contains(upper, "EXCEPTION") || strings.Contains(upper, "FAILED"):
		return model.HardeningLogLevelError
	case strings.Contains(upper, "WARN"):
		return model.HardeningLogLevelWarn
	case strings.Contains(upper, "SUCCESS") || strings.Contains(upper, "ALL DONE"):
		return model.HardeningLogLevelSuccess
	default:
		return fallback
	}
}
```

- [ ] **Step 4: Implement worker**

Create `internal/worker/hardening_worker.go`:

```go
package worker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type ObjectStorage interface {
	GetObjectToFile(ctx context.Context, objectKey string, destinationPath string) error
	PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string) error
}

type HardeningWorkerConfig struct {
	JarPath string
	WorkDir string
	DefaultVMPRules string
	Timeout time.Duration
}

type HardeningWorker struct {
	repo *repository.HardeningRepository
	appRepo *repository.AppRepository
	storage ObjectStorage
	runner EngineRunner
	cfg HardeningWorkerConfig
}

func NewHardeningWorker(repo *repository.HardeningRepository, appRepo *repository.AppRepository, storage ObjectStorage, runner EngineRunner, cfg HardeningWorkerConfig) *HardeningWorker {
	return &HardeningWorker{repo: repo, appRepo: appRepo, storage: storage, runner: runner, cfg: cfg}
}

func (w *HardeningWorker) RecoverRunning(ctx context.Context) error {
	ids, err := w.repo.RecoverRunningTasks("服务重启导致任务中断")
	if err != nil {
		return err
	}
	for _, id := range ids {
		task, err := w.repo.FindByID(id)
		if err == nil {
			_ = w.appRepo.UpdateStatus(task.AppID, model.AppStatusFailed)
		}
	}
	return nil
}

func (w *HardeningWorker) Start(ctx context.Context, interval time.Duration) {
	go func() {
		_ = w.RecoverRunning(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, _ = w.ProcessNext(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (w *HardeningWorker) ProcessNext(ctx context.Context) (bool, error) {
	task, err := w.repo.NextQueuedTask()
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	if err := w.repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		return false, err
	}
	if err := w.runTask(ctx, task); err != nil {
		now := time.Now()
		_ = w.repo.MarkTaskFailed(task.ID, err.Error(), now)
		_ = w.appRepo.UpdateStatus(task.AppID, model.AppStatusFailed)
		return true, nil
	}
	return true, nil
}

func (w *HardeningWorker) runTask(ctx context.Context, task *model.HardeningTask) error {
	timeout := w.cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Minute
	}
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	workDir := filepath.Join(w.cfg.WorkDir, task.TaskNo)
	ext := filepath.Ext(task.App.ObjectKey)
	if ext == "" {
		ext = ".apk"
	}
	inputPath := filepath.Join(workDir, "input"+ext)
	outputPath := filepath.Join(workDir, "output"+ext)
	rulesPath := filepath.Join(workDir, "vmp-rules.txt")

	if err := os.MkdirAll(workDir, 0700); err != nil {
		return err
	}
	if err := w.runStep(task.ID, model.HardeningStepPrepareInput, func(step *model.HardeningStep) error {
		if err := w.storage.GetObjectToFile(taskCtx, task.App.ObjectKey, inputPath); err != nil {
			return err
		}
		rules := service.NormalizeVMPRules(task.VMPRulesText, w.cfg.DefaultVMPRules)
		return os.WriteFile(rulesPath, []byte(rules), 0600)
	}); err != nil {
		return err
	}
	if err := w.runStep(task.ID, model.HardeningStepParsePackage, func(step *model.HardeningStep) error {
		return w.log(task.ID, &step.ID, model.HardeningLogLevelInfo, fmt.Sprintf("应用包名: %s, 版本: %s", task.App.PackageName, task.App.Version))
	}); err != nil {
		return err
	}
	command := service.BuildDPTCommand(service.EngineCommandInput{
		JavaBin: "java",
		JarPath: w.cfg.JarPath,
		InputPath: inputPath,
		OutputPath: outputPath,
		RulesPath: rulesPath,
		Strategy: task.StrategySnapshot,
		EnableFileIntegrityCheck: task.EnableFileIntegrityCheck,
		EnableProxyDetect: task.EnableProxyDetect,
	})
	if err := w.runStep(task.ID, model.HardeningStepApplyStrategy, func(step *model.HardeningStep) error {
		return w.log(task.ID, &step.ID, model.HardeningLogLevelInfo, "引擎命令: "+strings.Join(command, " "))
	}); err != nil {
		return err
	}
	if err := w.runStep(task.ID, model.HardeningStepRunEngine, func(step *model.HardeningStep) error {
		return w.runner.Run(taskCtx, EngineRunRequest{Command: command, WorkDir: workDir}, func(level model.HardeningLogLevel, line string) {
			_ = w.log(task.ID, &step.ID, level, line)
		})
	}); err != nil {
		return err
	}

	var unsigned service.ArtifactInfo
	var signed service.ArtifactInfo
	if err := w.runStep(task.ID, model.HardeningStepCollectArtifacts, func(step *model.HardeningStep) error {
		sum, size, err := service.SHA256File(outputPath)
		if err != nil {
			return fmt.Errorf("未生成未签名加固产物")
		}
		if size <= 0 {
			return fmt.Errorf("未签名加固产物为空")
		}
		unsigned = service.ArtifactInfo{Path: outputPath, ObjectKey: artifactObjectKey(task, "unsigned", ext), Size: size, SHA256: sum}
		signedPath := service.SignedTestArtifactPath(outputPath)
		if sum, size, err := service.SHA256File(signedPath); err == nil && size > 0 {
			signed = service.ArtifactInfo{Path: signedPath, ObjectKey: artifactObjectKey(task, "signed_test", ext), Size: size, SHA256: sum}
		} else {
			_ = w.log(task.ID, &step.ID, model.HardeningLogLevelWarn, "未发现测试签名产物")
		}
		return nil
	}); err != nil {
		return err
	}

	if err := w.runStep(task.ID, model.HardeningStepUploadArtifacts, func(step *model.HardeningStep) error {
		if err := w.uploadArtifact(taskCtx, unsigned); err != nil {
			return err
		}
		if signed.Path != "" {
			if err := w.uploadArtifact(taskCtx, signed); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	now := time.Now()
	if err := w.repo.MarkTaskCompleted(task.ID, unsigned.ObjectKey, unsigned.Size, unsigned.SHA256, signed.ObjectKey, signed.Size, signed.SHA256, now); err != nil {
		return err
	}
	return w.appRepo.UpdateStatus(task.AppID, model.AppStatusCompleted)
}

func (w *HardeningWorker) runStep(taskID uint, key model.HardeningStepKey, fn func(*model.HardeningStep) error) error {
	step, err := w.repo.FindStep(taskID, key)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := w.repo.StartStep(step.ID, now); err != nil {
		return err
	}
	if err := fn(step); err != nil {
		_ = w.repo.FinishStepFailed(step.ID, err.Error(), time.Now())
		_ = w.log(taskID, &step.ID, model.HardeningLogLevelError, err.Error())
		return err
	}
	return w.repo.FinishStepSuccess(step.ID, time.Now())
}

func (w *HardeningWorker) log(taskID uint, stepID *uint, level model.HardeningLogLevel, message string) error {
	return w.repo.AppendLog(&model.HardeningLog{TaskID: taskID, StepID: stepID, Level: level, Message: message})
}

func (w *HardeningWorker) uploadArtifact(ctx context.Context, artifact service.ArtifactInfo) error {
	file, err := os.Open(artifact.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	return w.storage.PutObject(ctx, artifact.ObjectKey, file, artifact.Size, "application/octet-stream")
}

func artifactObjectKey(task *model.HardeningTask, kind string, ext string) string {
	return fmt.Sprintf("%s/hardening/%s/%s%s", task.App.PackageName, task.TaskNo, kind, ext)
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
go test ./internal/worker -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/worker/engine.go internal/worker/hardening_worker.go internal/worker/hardening_worker_test.go
git commit -m "feat: add hardening worker"
```

---

### Task 6: HTTP Handlers, Routes, and Server Wiring

**Files:**
- Create: `internal/handler/hardening_handler.go`
- Create: `internal/handler/hardening_handler_test.go`
- Modify: `internal/router/router.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes `HardeningService`.
- Produces:
  - `handler.HardeningHandler`
  - `handler.NewHardeningHandler(svc *service.HardeningService) *HardeningHandler`
  - Methods: `Create`, `List`, `Get`, `Logs`, `DownloadURL`, `AppHistory`
  - `router.Deps.HardeningHandler *handler.HardeningHandler`
  - Routes:
    - `POST /api/v1/hardening-tasks`
    - `GET /api/v1/hardening-tasks`
    - `GET /api/v1/hardening-tasks/:id`
    - `GET /api/v1/hardening-tasks/:id/logs`
    - `GET /api/v1/hardening-tasks/:id/download-url`
    - `GET /api/v1/apps/:id/hardening-history`

- [ ] **Step 1: Write handler tests**

Create `internal/handler/hardening_handler_test.go` with tests for permissions, duplicate task, list/detail/logs/download/history. Use the same httptest + real router pattern as existing handler tests:

```go
package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

type fakeHardeningURLStorage struct{}

func (fakeHardeningURLStorage) PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error) {
	return "https://minio.example/" + objectKey, nil
}

func setupHardeningRouter(t *testing.T) (*httptest.Server, string, string, string, uint, *repository.HardeningRepository, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "hardening-handler-secret", JWTExpireHours: 1,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
	database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
	database.Exec("DELETE FROM hardening_tasks WHERE app_id IN (SELECT id FROM apps WHERE package_name LIKE 'com.hardening.handler.%')")
	database.Unscoped().Where("package_name LIKE ?", "com.hardening.handler.%").Delete(&model.App{})

	userRepo := repository.NewUserRepository(database)
	hashed, _ := hash.HashPassword("Password123!")
	users := []model.User{
		{Name: "Hardening Admin", Email: "hardening-admin@beetleshield.com", PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive},
		{Name: "Hardening Developer", Email: "hardening-developer@beetleshield.com", PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive},
		{Name: "Hardening Auditor", Email: "hardening-auditor@beetleshield.com", PasswordHash: hashed, Role: model.RoleAuditor, Status: model.UserStatusActive},
	}
	for i := range users {
		userRepo.DeleteByEmail(users[i].Email)
		if err := userRepo.Create(&users[i]); err != nil {
			t.Fatalf("create user: %v", err)
		}
	}
	authSvc := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	adminToken, _, _ := authSvc.Login(users[0].Email, "Password123!")
	developerToken, _, _ := authSvc.Login(users[1].Email, "Password123!")
	auditorToken, _, _ := authSvc.Login(users[2].Email, "Password123!")

	appRepo := repository.NewAppRepository(database)
	app := model.App{
		Name: "Handler App",
		PackageName: "com.hardening.handler.app",
		Version: "1.0.0",
		Tag: model.AppTagTool,
		Status: model.AppStatusUnprotected,
		ObjectKey: "handler/app.apk",
		MD5: "d41d8cd98f00b204e9800998ecf8427e",
		SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		UploadedBy: users[0].ID,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("create app: %v", err)
	}

	strategySvc := service.NewStrategyService(repository.NewStrategyRepository(database))
	hardeningRepo := repository.NewHardeningRepository(database)
	hardeningSvc := service.NewHardeningService(hardeningRepo, appRepo, strategySvc, fakeHardeningURLStorage{}, "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**")
	hardeningHandler := handler.NewHardeningHandler(hardeningSvc)

	r := router.New(router.Deps{
		JWTSecret: cfg.JWTSecret,
		AuthHandler: handler.NewAuthHandler(authSvc),
		HardeningHandler: hardeningHandler,
	})
	srv := httptest.NewServer(r)
	cleanup := func() {
		srv.Close()
		for _, user := range users {
			userRepo.DeleteByEmail(user.Email)
		}
		database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
		database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE 'TASK-%')")
		database.Exec("DELETE FROM hardening_tasks WHERE app_id IN (SELECT id FROM apps WHERE package_name LIKE 'com.hardening.handler.%')")
		database.Unscoped().Where("package_name LIKE ?", "com.hardening.handler.%").Delete(&model.App{})
	}
	return srv, adminToken, developerToken, auditorToken, app.ID, hardeningRepo, cleanup
}

func TestHardeningHandler_CreateDeveloperSucceedsAuditorForbidden(t *testing.T) {
	srv, _, developerToken, auditorToken, appID, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"appId": appID, "strategyName": "信息院 App 加固模板", "vmpRulesText": "com.example.**"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("developer create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("developer status = %d, want 200", resp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+auditorToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("auditor create request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor status = %d, want 403", resp2.StatusCode)
	}
}

func TestHardeningHandler_ListDetailLogsDownloadAndHistory(t *testing.T) {
	srv, adminToken, _, _, appID, repo, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"appId": appID})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	taskID := created.Data.Task.ID
	step := created.Data.Steps[0]
	if err := repo.AppendLog(&model.HardeningLog{TaskID: taskID, StepID: &step.ID, Level: model.HardeningLogLevelInfo, Message: "handler log"}); err != nil {
		t.Fatalf("append log: %v", err)
	}
	if err := repo.MarkTaskCompleted(taskID, "handler/unsigned.apk", 10, "abc", "handler/signed.apk", 11, "def", time.Now()); err != nil {
		t.Fatalf("mark completed: %v", err)
	}

	for _, path := range []string{
		"/api/v1/hardening-tasks",
		"/api/v1/hardening-tasks/" + strconv.Itoa(int(taskID)),
		"/api/v1/hardening-tasks/" + strconv.Itoa(int(taskID)) + "/logs",
		"/api/v1/hardening-tasks/" + strconv.Itoa(int(taskID)) + "/download-url?artifact=unsigned",
		"/api/v1/apps/" + strconv.Itoa(int(appID)) + "/hardening-history",
	} {
		getReq, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		getReq.Header.Set("Authorization", "Bearer "+adminToken)
		getResp, err := http.DefaultClient.Do(getReq)
		if err != nil {
			t.Fatalf("GET %s error: %v", path, err)
		}
		getResp.Body.Close()
		if getResp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, getResp.StatusCode)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/handler -run HardeningHandler -v
```

Expected: FAIL because `HardeningHandler` and routes are not defined.

- [ ] **Step 3: Implement handler**

Create `internal/handler/hardening_handler.go`:

```go
package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type HardeningHandler struct {
	svc *service.HardeningService
}

func NewHardeningHandler(svc *service.HardeningService) *HardeningHandler {
	return &HardeningHandler{svc: svc}
}

type createHardeningTaskRequest struct {
	AppID uint `json:"appId" binding:"required"`
	StrategyName string `json:"strategyName"`
	StrategySnapshot *model.Strategy `json:"strategySnapshot"`
	VMPRulesText string `json:"vmpRulesText"`
	EnableFileIntegrityCheck bool `json:"enableFileIntegrityCheck"`
	EnableProxyDetect bool `json:"enableProxyDetect"`
}

func (h *HardeningHandler) Create(c *gin.Context) {
	var req createHardeningTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40020, err.Error())
		return
	}
	detail, err := h.svc.Create(c.Request.Context(), service.CreateHardeningTaskInput{
		AppID: req.AppID,
		StrategyName: req.StrategyName,
		StrategySnapshot: req.StrategySnapshot,
		VMPRulesText: req.VMPRulesText,
		EnableFileIntegrityCheck: req.EnableFileIntegrityCheck,
		EnableProxyDetect: req.EnableProxyDetect,
		CreatedBy: c.GetUint(middleware.ContextUserIDKey),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrHardeningAppNotFound):
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
		case errors.Is(err, service.ErrHardeningActiveTaskExists):
			response.Error(c, http.StatusConflict, 40910, "应用已有进行中的加固任务")
		default:
			response.Error(c, http.StatusInternalServerError, 50020, "创建加固任务失败")
		}
		return
	}
	response.Success(c, http.StatusOK, detail)
}

func (h *HardeningHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	appID64, _ := strconv.ParseUint(c.DefaultQuery("appId", "0"), 10, 64)
	items, total, err := h.svc.List(repository.HardeningListFilter{
		Status: c.Query("status"),
		AppID: uint(appID64),
		Search: c.Query("search"),
		Page: page,
		PageSize: pageSize,
	})
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50021, "查询加固任务失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"items": items, "total": total})
}

func (h *HardeningHandler) Get(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	detail, err := h.svc.Get(id)
	if err != nil {
		if errors.Is(err, service.ErrHardeningTaskNotFound) {
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50021, "查询加固任务失败")
		return
	}
	response.Success(c, http.StatusOK, detail)
}

func (h *HardeningHandler) Logs(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	afterID64, _ := strconv.ParseUint(c.DefaultQuery("afterId", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	logs, err := h.svc.Logs(id, repository.HardeningLogFilter{StepKey: model.HardeningStepKey(c.Query("stepKey")), AfterID: uint(afterID64), Limit: limit})
	if err != nil {
		if errors.Is(err, service.ErrHardeningTaskNotFound) {
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50021, "查询加固日志失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"items": logs})
}

func (h *HardeningHandler) DownloadURL(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	url, err := h.svc.DownloadURL(c.Request.Context(), id, c.Query("artifact"))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrHardeningTaskNotFound):
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
		case errors.Is(err, service.ErrHardeningArtifactNotFound):
			response.Error(c, http.StatusNotFound, 40411, "加固产物不存在")
		case errors.Is(err, service.ErrInvalidHardeningArtifact):
			response.Error(c, http.StatusBadRequest, 40020, "非法产物类型")
		default:
			response.Error(c, http.StatusInternalServerError, 50022, "生成产物下载链接失败")
		}
		return
	}
	response.Success(c, http.StatusOK, gin.H{"url": url})
}

func (h *HardeningHandler) AppHistory(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	items, err := h.svc.History(id)
	if err != nil {
		if errors.Is(err, service.ErrHardeningAppNotFound) {
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50021, "查询应用加固历史失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"items": items})
}

func parseUintParam(c *gin.Context, name string) (uint, bool) {
	id, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40021, "非法任务 ID")
		return 0, false
	}
	return uint(id), true
}
```

- [ ] **Step 4: Wire routes**

Modify `internal/router/router.go`:

```go
type Deps struct {
	JWTSecret       string
	AuthHandler     *handler.AuthHandler
	AppHandler      *handler.AppHandler
	UserHandler     *handler.UserHandler
	StrategyHandler *handler.StrategyHandler
	HardeningHandler *handler.HardeningHandler
}
```

Inside `/apps` group, add:

```go
apps.GET("/:id/hardening-history", deps.HardeningHandler.AppHistory)
```

After `strategies` group, add:

```go
hardeningTasks := v1.Group("/hardening-tasks")
hardeningTasks.Use(middleware.JWTAuth(deps.JWTSecret))
{
	hardeningTasks.POST("", writeRoles, deps.HardeningHandler.Create)
	hardeningTasks.GET("", deps.HardeningHandler.List)
	hardeningTasks.GET("/:id", deps.HardeningHandler.Get)
	hardeningTasks.GET("/:id/logs", deps.HardeningHandler.Logs)
	hardeningTasks.GET("/:id/download-url", deps.HardeningHandler.DownloadURL)
}
```

- [ ] **Step 5: Wire main**

Modify `cmd/server/main.go` after strategy wiring:

```go
hardeningRepo := repository.NewHardeningRepository(database)
hardeningService := service.NewHardeningService(hardeningRepo, appRepo, strategyService, storageClient, cfg.DPTDefaultVMPRules)
hardeningHandler := handler.NewHardeningHandler(hardeningService)
```

Add `HardeningHandler: hardeningHandler,` to `router.New`.

Worker startup is added in Task 7 after README/manual smoke updates.

- [ ] **Step 6: Run tests**

Run:

```bash
go test ./internal/handler ./internal/router/... -run 'HardeningHandler|Router' -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/handler/hardening_handler.go internal/handler/hardening_handler_test.go internal/router/router.go cmd/server/main.go
git commit -m "feat: expose hardening task APIs"
```

---

### Task 7: Start Worker in Server and Add Manual Smoke Documentation

**Files:**
- Modify: `cmd/server/main.go`
- Modify: `README.md`

**Interfaces:**
- Consumes `worker.NewHardeningWorker`, `worker.DPTRunner`, config, repositories, and storage client.
- Produces server startup behavior: recover stale running tasks, then poll queued tasks every 3 seconds.

- [ ] **Step 1: Write compile-time startup change**

Modify imports in `cmd/server/main.go` to include:

```go
"time"

"beetleshield-backend/internal/worker"
```

After `hardeningHandler := handler.NewHardeningHandler(hardeningService)`, add:

```go
hardeningWorker := worker.NewHardeningWorker(
	hardeningRepo,
	appRepo,
	storageClient,
	worker.DPTRunner{},
	worker.HardeningWorkerConfig{
		JarPath: cfg.DPTJarPath,
		WorkDir: cfg.DPTWorkDir,
		DefaultVMPRules: cfg.DPTDefaultVMPRules,
		Timeout: time.Duration(cfg.DPTTaskTimeoutMinutes) * time.Minute,
	},
)
hardeningWorker.Start(context.Background(), 3*time.Second)
```

`context` is already imported in `cmd/server/main.go`; keep a single import.

- [ ] **Step 2: Update README API overview**

Append these bullets under “API overview” in `README.md`:

```markdown
- `POST /hardening-tasks` — create a queued hardening task for an existing app (`admin`/`developer`)
- `GET /hardening-tasks?status=&appId=&search=&page=&pageSize=` — list hardening tasks
- `GET /hardening-tasks/:id` — task detail with steps and recent logs
- `GET /hardening-tasks/:id/logs?stepKey=&afterId=&limit=` — task logs
- `GET /hardening-tasks/:id/download-url?artifact=unsigned|signed_test` — presigned artifact download URL
- `GET /apps/:id/hardening-history` — recent hardening history for an app
```

Append a “Manual hardening smoke test” section:

```markdown
## Manual hardening smoke test

The default test suite does not run `dpt.jar`. To test the real engine locally:

1. Ensure `.env` points `DPT_JAR_PATH` at `/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar`.
2. Upload an APK through `POST /apps/upload`.
3. Create a hardening task with `POST /hardening-tasks`.
4. Poll `GET /hardening-tasks/:id` until the task is `completed` or `failed`.
5. Download the unsigned artifact with `GET /hardening-tasks/:id/download-url?artifact=unsigned`.
6. Optionally download the test signed artifact with `artifact=signed_test` if present.
```

- [ ] **Step 3: Run full package tests**

Run:

```bash
go test ./...
```

Expected: PASS if local Postgres and MinIO are running and configured like the existing test suite expects.

- [ ] **Step 4: Run targeted build**

Run:

```bash
go test ./cmd/server ./internal/worker ./internal/service ./internal/handler -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/server/main.go README.md
git commit -m "feat: start hardening worker"
```

---

## Self-Review Checklist

- Spec coverage:
  - Data models and migrations: Task 1.
  - Queue, steps, logs, history, recovery persistence: Task 2.
  - Strategy snapshot command mapping and VMP rules default/custom behavior: Tasks 3 and 4.
  - Serial worker and dpt runner: Task 5.
  - HTTP APIs and permissions: Task 6.
  - Server startup and manual smoke path: Task 7.
- Marker scan: no unresolved marker strings remain. Each task contains concrete files, interfaces, commands, and expected outcomes.
- Type consistency:
  - Repository filter names match service/handler usage: `HardeningListFilter`, `HardeningLogFilter`.
  - Artifact name values match the spec and handler: `unsigned`, `signed_test`.
  - Step keys match the fixed six-step spec.
  - Task status and app status transitions match the spec.
