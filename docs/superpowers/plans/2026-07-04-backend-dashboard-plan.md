# BeetleShield Backend — Dashboard Overview (Sub-project 8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the frontend "总览" (Dashboard) page's mock data with a real backend-computed overview — today's task stats, 24h trend, result distribution, recent tasks, risk-app Top5, and a simplified system status — exposed via `GET /api/v1/hardening-tasks/overview`, and persist `App.RiskLevel` for the first time (written when a hardening task completes).

**Architecture:** No new table, no new migration. `App.RiskLevel` (existing, never-written field) gets written inside the same transaction that already marks a task completed. A new `service.ResolveRiskLevel` shares its scoring math with the existing `service.BuildHardeningReport` via an extracted `computeScoreBreakdown` helper, so the two can never drift. A new `DashboardService` aggregates several small, focused repository queries into one read-only response — no new state, purely computed on read.

**Tech Stack:** Same as existing codebase — Go, Gin, GORM/Postgres, no new dependencies. Frontend: React + TypeScript + antd + `@ant-design/charts`, existing `src/api/*.ts` axios-wrapper pattern.

Reference spec: [`docs/superpowers/specs/2026-07-04-backend-dashboard-design.md`](../specs/2026-07-04-backend-dashboard-design.md)

## Global Constraints

- Module name: `beetleshield-backend`. API prefix `/api/v1`; unified `{code,message,data}` envelope via `internal/pkg/response`.
- Local dev Postgres: `root`/`root`@`localhost:5432`/`beetleshield` (pre-existing `pg12-dev` container). Shared DB is not pristine — scope test assertions with unique identifiers or before/after deltas, never table-wide absolute counts, matching every existing `internal/service/*_test.go` and `internal/handler/*_test.go` file.
- No database migration needed — `App.RiskLevel` column already exists; this sub-project only starts writing to it.
- **No historical backfill**: apps that completed hardening before this change ships keep `RiskLevel = NULL` until their next hardening run.
- `GET /api/v1/hardening-tasks/overview` is readable by any authenticated role (`JWTAuth` only, no `RequireRole`), matching the sibling `GET /:id` and `GET /:id/report`.
- No environ-comparison ("较昨日") trends, no numeric risk score persisted on `App` (only the 4-level `RiskLevel` enum), no multi-node worker status display — all explicitly out of scope per the design doc.
- **Before starting Task 2 onward, make sure no other process is writing to the same dev Postgres** (e.g. a `go run ./cmd/server` / hardening worker left running from manual testing) — several new tests below rely on "nothing else touches `hardening_tasks`/`apps` during this test" to make exact assertions against the shared, non-pristine database.

---

## File Structure

```
internal/
├── service/
│   ├── hardening_report.go         (modify — extract computeScoreBreakdown, add ResolveRiskLevel)
│   ├── hardening_report_test.go    (modify — add ResolveRiskLevel tests)
│   ├── dashboard_service.go        (new — DashboardOverview type + DashboardService.GetOverview)
│   └── dashboard_service_test.go   (new)
├── repository/
│   ├── hardening_repository.go     (modify — CompleteTaskForApp gains riskLevel param; transitionTaskForApp/Tx takes appUpdates map; 5 new query methods)
│   ├── hardening_repository_test.go (modify — update CompleteTaskForApp call sites + add new query method tests)
│   ├── app_repository.go           (modify — add TopByRiskLevel)
│   └── app_repository_test.go      (modify — add TopByRiskLevel test)
├── worker/
│   ├── hardening_worker.go         (modify — compute and pass riskLevel before CompleteTaskForApp)
│   └── hardening_worker_test.go    (modify — update CompleteTaskForApp call site; add risk-level persistence test)
├── service/hardening_service_test.go (modify — update 2 CompleteTaskForApp call sites)
├── service/audit_retrofit_test.go    (modify — update 1 CompleteTaskForApp call site)
├── handler/
│   ├── hardening_handler.go        (modify — HardeningHandler gains dashboardSvc + GetOverview)
│   └── hardening_handler_test.go   (modify — setupHardeningRouter constructs DashboardService; add GetOverview test)
└── router/
    └── router.go                   (modify — GET /hardening-tasks/overview route, registered before /:id)
cmd/server/main.go                   (modify — construct DashboardService, pass into NewHardeningHandler)
```

Frontend (`/Users/yrighc/work/hzyz/project/BeetleShieldFrontend`):
```
src/api/types.ts        (modify — add DashboardOverview and related interfaces)
src/api/dashboard.ts     (new — getDashboardOverview)
src/pages/Dashboard.tsx  (modify — replace all mock data with real API calls)
```

---

### Task 1: Extract `computeScoreBreakdown` + add `ResolveRiskLevel`

**Files:**
- Modify: `internal/service/hardening_report.go`
- Modify: `internal/service/hardening_report_test.go`

**Interfaces:**
- Produces: `service.ResolveRiskLevel(strategy model.Strategy) model.RiskLevel` — consumed by Task 2 (worker) and reused internally by `BuildHardeningReport`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/service/hardening_report_test.go` (package is `service_test`, already imports `model` and `service`; reuses the existing `fullyHardenedStrategy()` and `baseReportTask()` helpers defined earlier in this same file):

```go
func TestResolveRiskLevel_NoStrategyIsCritical(t *testing.T) {
	if got := service.ResolveRiskLevel(model.Strategy{}); got != model.RiskLevelCritical {
		t.Fatalf("ResolveRiskLevel(empty) = %q, want %q", got, model.RiskLevelCritical)
	}
}

func TestResolveRiskLevel_FullyHardenedIsLow(t *testing.T) {
	if got := service.ResolveRiskLevel(fullyHardenedStrategy()); got != model.RiskLevelLow {
		t.Fatalf("ResolveRiskLevel(fully hardened) = %q, want %q", got, model.RiskLevelLow)
	}
}

func TestResolveRiskLevel_MatchesBuildHardeningReportRiskLevel(t *testing.T) {
	cases := []model.Strategy{
		{},
		fullyHardenedStrategy(),
		{Emulator: true, RootDetect: true},
		{Frida: true, DexLevel: model.DexLevelHigh},
		{Debugger: true},
	}

	for i, strategy := range cases {
		got := service.ResolveRiskLevel(strategy)
		want := service.BuildHardeningReport(baseReportTask(strategy), "v1").RiskLevel
		if got != want {
			t.Fatalf("case %d: ResolveRiskLevel(%+v) = %q, want %q (must match BuildHardeningReport, same scoring math)", i, strategy, got, want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/service/... -run TestResolveRiskLevel -v`
Expected: FAIL — `undefined: service.ResolveRiskLevel`

- [ ] **Step 3: Extract `computeScoreBreakdown` and add `ResolveRiskLevel`**

In `internal/service/hardening_report.go`, replace the body of `BuildHardeningReport` from its start through the `dimensions := []ReportDimension{...}` block:

Replace:

```go
func BuildHardeningReport(task model.HardeningTask, engineVersion string) HardeningReport {
	flags := ResolveEffectiveFlags(task.StrategySnapshot)

	antiDebugEnvScore := boolScore(flags.EmulatorDetect || flags.RootDetect, weightAntiDebugEnv)
	hookScore := boolScore(flags.HookDetect, weightHookDefense)
	sigScore := boolScore(flags.SigVerify, weightSignature)
	dexPoints := dexScore(task.StrategySnapshot.DexLevel)
	soPoints := boolScore(flags.VMPEnabled, weightSoShellMax)
	encryptPoints := encryptionScore(flags)

	afterScore := 100 - (antiDebugEnvScore + hookScore + sigScore + dexPoints + soPoints + encryptPoints)
	if afterScore < reportMinAfterScore {
		afterScore = reportMinAfterScore
	}

	antiDebugCombinedWeight := weightAntiDebugEnv + weightHookDefense
	antiDebugCombinedPercent := (antiDebugEnvScore + hookScore) * 100 / antiDebugCombinedWeight

	dimensions := []ReportDimension{
		{Name: "反调试保护", Before: 0, After: antiDebugCombinedPercent},
		{Name: "DEX 混淆", Before: 0, After: dexPoints * 100 / weightDexMax},
		{Name: "SO 加壳保护", Before: 0, After: soPoints * 100 / weightSoShellMax},
		{Name: "资源文件加密", Before: 0, After: encryptPoints * 100 / weightEncryptionMax},
		{Name: "签名校验", Before: 0, After: sigScore * 100 / weightSignature},
	}
```

With:

```go
type scoreBreakdown struct {
	antiDebugEnvScore int
	hookScore         int
	sigScore          int
	dexPoints         int
	soPoints          int
	encryptPoints     int
	afterScore        int
}

// computeScoreBreakdown is the single source of truth for turning a
// Strategy's effective flags into the overall risk score. BuildHardeningReport
// (the human-readable report) and ResolveRiskLevel (the value persisted onto
// App.RiskLevel when a task completes) both call this, so the two can never
// silently drift apart.
func computeScoreBreakdown(flags EffectiveFlags, dexLevel model.DexObfuscationLevel) scoreBreakdown {
	antiDebugEnvScore := boolScore(flags.EmulatorDetect || flags.RootDetect, weightAntiDebugEnv)
	hookScore := boolScore(flags.HookDetect, weightHookDefense)
	sigScore := boolScore(flags.SigVerify, weightSignature)
	dexPoints := dexScore(dexLevel)
	soPoints := boolScore(flags.VMPEnabled, weightSoShellMax)
	encryptPoints := encryptionScore(flags)

	afterScore := 100 - (antiDebugEnvScore + hookScore + sigScore + dexPoints + soPoints + encryptPoints)
	if afterScore < reportMinAfterScore {
		afterScore = reportMinAfterScore
	}

	return scoreBreakdown{
		antiDebugEnvScore: antiDebugEnvScore,
		hookScore:         hookScore,
		sigScore:          sigScore,
		dexPoints:         dexPoints,
		soPoints:          soPoints,
		encryptPoints:     encryptPoints,
		afterScore:        afterScore,
	}
}

// ResolveRiskLevel computes the risk level for a completed task's strategy —
// the same computation BuildHardeningReport uses internally. Exported so the
// worker can persist App.RiskLevel at completion time without duplicating
// (and risking drift from) the report's scoring logic.
func ResolveRiskLevel(strategy model.Strategy) model.RiskLevel {
	flags := ResolveEffectiveFlags(strategy)
	breakdown := computeScoreBreakdown(flags, strategy.DexLevel)
	return riskLevelForScore(breakdown.afterScore)
}

func BuildHardeningReport(task model.HardeningTask, engineVersion string) HardeningReport {
	flags := ResolveEffectiveFlags(task.StrategySnapshot)
	b := computeScoreBreakdown(flags, task.StrategySnapshot.DexLevel)

	antiDebugCombinedWeight := weightAntiDebugEnv + weightHookDefense
	antiDebugCombinedPercent := (b.antiDebugEnvScore + b.hookScore) * 100 / antiDebugCombinedWeight

	dimensions := []ReportDimension{
		{Name: "反调试保护", Before: 0, After: antiDebugCombinedPercent},
		{Name: "DEX 混淆", Before: 0, After: b.dexPoints * 100 / weightDexMax},
		{Name: "SO 加壳保护", Before: 0, After: b.soPoints * 100 / weightSoShellMax},
		{Name: "资源文件加密", Before: 0, After: b.encryptPoints * 100 / weightEncryptionMax},
		{Name: "签名校验", Before: 0, After: b.sigScore * 100 / weightSignature},
	}
```

Further down in the same function, the `checklist` block and everything through `unsignedFileName := ...` stays **unchanged** (it already reads `flags.*` and `task.StrategySnapshot.DexLevel` directly, not the removed local variables).

Then replace the final `return HardeningReport{...}` block's two score-related lines:

Replace:

```go
		BeforeScore: 100,
		AfterScore:  afterScore,
		RiskLevel:   riskLevelForScore(afterScore),
```

With:

```go
		BeforeScore: 100,
		AfterScore:  b.afterScore,
		RiskLevel:   riskLevelForScore(b.afterScore),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/service/... -run 'TestResolveRiskLevel|TestBuildHardeningReport' -v`
Expected: PASS for all `TestResolveRiskLevel_*` and every pre-existing `TestBuildHardeningReport_*` test (proving the refactor preserved exact behavior).

- [ ] **Step 5: Commit**

```bash
git add internal/service/hardening_report.go internal/service/hardening_report_test.go
git commit -m "refactor: extract computeScoreBreakdown, add ResolveRiskLevel"
```

---

### Task 2: Persist `App.RiskLevel` when a hardening task completes

**Files:**
- Modify: `internal/repository/hardening_repository.go`
- Modify: `internal/repository/hardening_repository_test.go`
- Modify: `internal/service/hardening_service_test.go`
- Modify: `internal/service/audit_retrofit_test.go`
- Modify: `internal/handler/hardening_handler_test.go`
- Modify: `internal/worker/hardening_worker.go`
- Modify: `internal/worker/hardening_worker_test.go`

**Interfaces:**
- Consumes: `service.ResolveRiskLevel` (Task 1).
- Produces: `HardeningRepository.CompleteTaskForApp(..., riskLevel model.RiskLevel) error` (signature change — every existing caller must be updated in this task); `HardeningRepository.transitionTaskForApp`/`transitionTaskForAppTx` now take `appUpdates map[string]interface{}` instead of a single `appStatus model.AppStatus`.

- [ ] **Step 1: Update the existing atomic-completion test to expect a persisted risk level**

In `internal/repository/hardening_repository_test.go`, find `TestHardeningRepository_CompleteTaskForAppUpdatesTaskAndAppAtomically` and change the `CompleteTaskForApp` call plus add a risk-level assertion:

Replace:

```go
	if err := repo.CompleteTaskForApp(task.ID, "unsigned.apk", 12, "abc", "signed.apk", 13, "def", now.Add(time.Second)); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	foundTask, err := repo.FindByID(task.ID)
	if err != nil {
		t.Fatalf("FindByID() task error = %v", err)
	}
	if foundTask.Status != model.HardeningTaskStatusCompleted {
		t.Fatalf("task status = %s, want completed", foundTask.Status)
	}

	foundApp, err := appRepo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() app error = %v", err)
	}
	if foundApp.Status != model.AppStatusCompleted {
		t.Fatalf("app status = %s, want completed", foundApp.Status)
	}
}
```

With:

```go
	if err := repo.CompleteTaskForApp(task.ID, "unsigned.apk", 12, "abc", "signed.apk", 13, "def", now.Add(time.Second), model.RiskLevelHigh); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	foundTask, err := repo.FindByID(task.ID)
	if err != nil {
		t.Fatalf("FindByID() task error = %v", err)
	}
	if foundTask.Status != model.HardeningTaskStatusCompleted {
		t.Fatalf("task status = %s, want completed", foundTask.Status)
	}

	foundApp, err := appRepo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() app error = %v", err)
	}
	if foundApp.Status != model.AppStatusCompleted {
		t.Fatalf("app status = %s, want completed", foundApp.Status)
	}
	if foundApp.RiskLevel == nil || *foundApp.RiskLevel != model.RiskLevelHigh {
		t.Fatalf("app risk level = %v, want %q", foundApp.RiskLevel, model.RiskLevelHigh)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repository/... -run TestHardeningRepository_CompleteTaskForAppUpdatesTaskAndAppAtomically -v`
Expected: FAIL — compile error, `not enough arguments in call to repo.CompleteTaskForApp`.

- [ ] **Step 3: Update `hardening_repository.go`**

Replace `CompleteTaskForApp`:

```go
func (r *HardeningRepository) CompleteTaskForApp(taskID uint, unsignedKey string, unsignedSize int64, unsignedSHA string, signedKey string, signedSize int64, signedSHA string, finishedAt time.Time) error {
	return r.transitionTaskForApp(taskID, model.HardeningTaskStatusRunning, map[string]interface{}{
		"status":                 model.HardeningTaskStatusCompleted,
		"unsigned_object_key":    unsignedKey,
		"unsigned_file_size":     unsignedSize,
		"unsigned_sha256":        unsignedSHA,
		"signed_test_object_key": signedKey,
		"signed_test_file_size":  signedSize,
		"signed_test_sha256":     signedSHA,
		"finished_at":            finishedAt,
		"error_summary":          "",
	}, model.AppStatusCompleted)
}
```

With:

```go
func (r *HardeningRepository) CompleteTaskForApp(taskID uint, unsignedKey string, unsignedSize int64, unsignedSHA string, signedKey string, signedSize int64, signedSHA string, finishedAt time.Time, riskLevel model.RiskLevel) error {
	return r.transitionTaskForApp(taskID, model.HardeningTaskStatusRunning, map[string]interface{}{
		"status":                 model.HardeningTaskStatusCompleted,
		"unsigned_object_key":    unsignedKey,
		"unsigned_file_size":     unsignedSize,
		"unsigned_sha256":        unsignedSHA,
		"signed_test_object_key": signedKey,
		"signed_test_file_size":  signedSize,
		"signed_test_sha256":     signedSHA,
		"finished_at":            finishedAt,
		"error_summary":          "",
	}, map[string]interface{}{
		"status":     model.AppStatusCompleted,
		"risk_level": riskLevel,
	})
}
```

Replace `FailTaskForApp`:

```go
func (r *HardeningRepository) FailTaskForApp(taskID uint, summary string, finishedAt time.Time) error {
	updates := map[string]interface{}{
		"status":        model.HardeningTaskStatusFailed,
		"error_summary": summary,
		"finished_at":   finishedAt,
	}
	for k, v := range failedTaskArtifactFields {
		updates[k] = v
	}
	return r.transitionTaskForApp(taskID, model.HardeningTaskStatusRunning, updates, model.AppStatusFailed)
}
```

With:

```go
func (r *HardeningRepository) FailTaskForApp(taskID uint, summary string, finishedAt time.Time) error {
	updates := map[string]interface{}{
		"status":        model.HardeningTaskStatusFailed,
		"error_summary": summary,
		"finished_at":   finishedAt,
	}
	for k, v := range failedTaskArtifactFields {
		updates[k] = v
	}
	return r.transitionTaskForApp(taskID, model.HardeningTaskStatusRunning, updates, map[string]interface{}{
		"status": model.AppStatusFailed,
	})
}
```

Replace `transitionTaskForApp` and `transitionTaskForAppTx`:

```go
func (r *HardeningRepository) transitionTaskForApp(taskID uint, expectedStatus model.HardeningTaskStatus, taskUpdates map[string]interface{}, appStatus model.AppStatus) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		task, err := lockHardeningTask(tx, taskID)
		if err != nil {
			return err
		}
		return transitionTaskForAppTx(tx, task.ID, task.AppID, expectedStatus, taskUpdates, appStatus)
	})
}

func transitionTaskForAppTx(tx *gorm.DB, taskID uint, appID uint, expectedStatus model.HardeningTaskStatus, taskUpdates map[string]interface{}, appStatus model.AppStatus) error {
	if err := requireUpdatedRow(tx.Model(&model.HardeningTask{}).
		Where("id = ? AND status = ?", taskID, expectedStatus).
		Updates(taskUpdates)); err != nil {
		return err
	}
	return requireUpdatedRow(tx.Model(&model.App{}).
		Where("id = ?", appID).
		Update("status", appStatus))
}
```

With:

```go
func (r *HardeningRepository) transitionTaskForApp(taskID uint, expectedStatus model.HardeningTaskStatus, taskUpdates map[string]interface{}, appUpdates map[string]interface{}) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		task, err := lockHardeningTask(tx, taskID)
		if err != nil {
			return err
		}
		return transitionTaskForAppTx(tx, task.ID, task.AppID, expectedStatus, taskUpdates, appUpdates)
	})
}

func transitionTaskForAppTx(tx *gorm.DB, taskID uint, appID uint, expectedStatus model.HardeningTaskStatus, taskUpdates map[string]interface{}, appUpdates map[string]interface{}) error {
	if err := requireUpdatedRow(tx.Model(&model.HardeningTask{}).
		Where("id = ? AND status = ?", taskID, expectedStatus).
		Updates(taskUpdates)); err != nil {
		return err
	}
	return requireUpdatedRow(tx.Model(&model.App{}).
		Where("id = ?", appID).
		Updates(appUpdates))
}
```

In `RecoverRunningTasks`, replace the call:

```go
			if err := transitionTaskForAppTx(tx, task.ID, task.AppID, model.HardeningTaskStatusRunning, taskUpdates, model.AppStatusFailed); err != nil {
				return err
			}
```

With:

```go
			if err := transitionTaskForAppTx(tx, task.ID, task.AppID, model.HardeningTaskStatusRunning, taskUpdates, map[string]interface{}{
				"status": model.AppStatusFailed,
			}); err != nil {
				return err
			}
```

- [ ] **Step 4: Fix every remaining `CompleteTaskForApp` call site**

In `internal/repository/hardening_repository_test.go`, there is one more call site (a different test) — search for `repo.CompleteTaskForApp(` and confirm only the one from Step 1 remains (it was the only other one in this file per current source).

In `internal/service/hardening_service_test.go`, two call sites — both look like:

```go
	if err := repo.CompleteTaskForApp(detail.Task.ID, "hardening/unsigned.apk", 10, "abc", "hardening/signed.apk", 11, "def", now); err != nil {
```

and

```go
	if err := repo.CompleteTaskForApp(detail.Task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", now); err != nil {
```

Append `, model.RiskLevelLow` before the closing `)` on both lines (immediately after `now`).

In `internal/service/audit_retrofit_test.go`, one call site:

```go
	if err := hardeningRepo.CompleteTaskForApp(detail.Task.ID, "hardening/unsigned-download.apk", 10, "abc", "", 0, "", now); err != nil {
```

Append `, model.RiskLevelLow` before the closing `)`.

In `internal/handler/hardening_handler_test.go`, three call sites:

```go
	if err := repo.CompleteTaskForApp(taskID, "handler/unsigned.apk", 10, "abc", "", 0, "", now); err != nil {
```

```go
	if err := hardeningRepo.CompleteTaskForApp(created.Data.Task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", now); err != nil {
```

```go
	if err := repo.CompleteTaskForApp(taskID, "handler/rbac-unsigned.apk", 10, "abc", "", 0, "", now); err != nil {
```

Append `, model.RiskLevelLow` before the closing `)` on all three.

In `internal/worker/hardening_worker.go`, replace:

```go
	now := time.Now()
	if err := w.repo.CompleteTaskForApp(task.ID, unsigned.ObjectKey, unsigned.Size, unsigned.SHA256, signed.ObjectKey, signed.Size, signed.SHA256, now); err != nil {
		return fmt.Errorf("persist task completion: %w", err)
	}
```

With:

```go
	now := time.Now()
	riskLevel := service.ResolveRiskLevel(task.StrategySnapshot)
	if err := w.repo.CompleteTaskForApp(task.ID, unsigned.ObjectKey, unsigned.Size, unsigned.SHA256, signed.ObjectKey, signed.Size, signed.SHA256, now, riskLevel); err != nil {
		return fmt.Errorf("persist task completion: %w", err)
	}
```

(`internal/worker/hardening_worker.go` already imports `beetleshield-backend/internal/service`.)

- [ ] **Step 5: Build to verify everything compiles**

Run: `go build ./... && go vet ./...`
Expected: no errors.

- [ ] **Step 6: Add a worker test proving `App.RiskLevel` is actually persisted end-to-end**

Append to `internal/worker/hardening_worker_test.go`:

```go
func TestHardeningWorker_ProcessNextPersistsAppRiskLevel(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "risklevel")

	processed, err := w.ProcessNext(context.Background())
	if err != nil {
		t.Fatalf("ProcessNext() error = %v", err)
	}
	if !processed {
		t.Fatal("processed = false, want true")
	}

	app, err := appRepo.FindByID(task.AppID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if app.RiskLevel == nil {
		t.Fatal("app.RiskLevel = nil, want medium")
	}
	// createWorkerTask's StrategySnapshot is {DexLevel: high, SoShell: vmp,
	// RootDetect: true, Signature: true}: antiDebugEnvScore=15 (RootDetect),
	// hookScore=0, sigScore=15, dexPoints=20 (high), soPoints=20 (vmp),
	// encryptPoints=0 -> sum=70 -> afterScore=30 -> medium (25<=30<50).
	if *app.RiskLevel != model.RiskLevelMedium {
		t.Fatalf("app.RiskLevel = %q, want %q", *app.RiskLevel, model.RiskLevelMedium)
	}
}
```

- [ ] **Step 7: Run the full affected test set**

Run: `go test ./internal/repository/... ./internal/service/... ./internal/handler/... ./internal/worker/... -run 'CompleteTaskForApp|FailTaskForApp|ProcessNextPersistsAppRiskLevel|ProcessNextSuccessUploadsArtifacts|RecoverRunning' -v`
Expected: PASS for every matched test, including the pre-existing ones (proves the signature change didn't silently break failure/recovery paths).

Then run each full package once to catch anything the `-run` filter missed:

Run: `go test ./internal/repository/... ./internal/service/... ./internal/handler/... ./internal/worker/... -v 2>&1 | tail -60`
Expected: `ok` for all four packages.

- [ ] **Step 8: Commit**

```bash
git add internal/repository/hardening_repository.go internal/repository/hardening_repository_test.go \
  internal/service/hardening_service_test.go internal/service/audit_retrofit_test.go \
  internal/handler/hardening_handler_test.go \
  internal/worker/hardening_worker.go internal/worker/hardening_worker_test.go
git commit -m "feat: persist App.RiskLevel when a hardening task completes"
```

---

### Task 3: Dashboard-supporting query methods on `HardeningRepository`

**Files:**
- Modify: `internal/repository/hardening_repository.go`
- Modify: `internal/repository/hardening_repository_test.go`

**Interfaces:**
- Produces: `HardeningRepository.CountByStatusSince(since time.Time) (map[model.HardeningTaskStatus]int64, error)`, `HardeningRepository.HourlyCountsSince(since time.Time) ([24]int64, error)`, `HardeningRepository.AverageCompletedDurationSince(since time.Time) (avgSeconds float64, ok bool, err error)`, `HardeningRepository.QueueCount() (int64, error)`, `HardeningRepository.Recent(limit int) ([]model.HardeningTask, error)` — all consumed by Task 5 (`DashboardService`).

These take an explicit `since` cutoff (rather than hardcoding "today" inside the repository) specifically so tests can pick a cutoff that excludes every pre-existing row in the shared dev database — `DashboardService` (Task 5) is the one place that decides "since" means "today, local midnight".

- [ ] **Step 1: Write the failing tests**

Append to `internal/repository/hardening_repository_test.go`:

```go
func TestHardeningRepository_CountByStatusSinceCountsOnlyTasksAtOrAfterCutoff(t *testing.T) {
	repo, appRepo, database, scope := setupHardeningRepo(t)
	since := time.Now()

	completedApp := createRepoApp(t, appRepo, scope, "count-completed")
	completedTask := newRepoTask(scope, "count-completed", completedApp.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&completedTask); err != nil {
		t.Fatalf("CreateTaskWithSteps() completed error = %v", err)
	}
	if err := repo.MarkTaskRunning(completedTask.ID, since.Add(time.Second)); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := repo.CompleteTaskForApp(completedTask.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", since.Add(2*time.Second), model.RiskLevelLow); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	failedApp := createRepoApp(t, appRepo, scope, "count-failed")
	failedTask := newRepoTask(scope, "count-failed", failedApp.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&failedTask); err != nil {
		t.Fatalf("CreateTaskWithSteps() failed error = %v", err)
	}
	if err := repo.MarkTaskRunning(failedTask.ID, since.Add(time.Second)); err != nil {
		t.Fatalf("MarkTaskRunning() failed error = %v", err)
	}
	if err := repo.FailTaskForApp(failedTask.ID, "engine crashed", since.Add(2*time.Second)); err != nil {
		t.Fatalf("FailTaskForApp() error = %v", err)
	}

	beforeCutoffApp := createRepoApp(t, appRepo, scope, "count-old")
	beforeCutoffTask := newRepoTask(scope, "count-old", beforeCutoffApp.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&beforeCutoffTask); err != nil {
		t.Fatalf("CreateTaskWithSteps() old error = %v", err)
	}
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", beforeCutoffTask.ID).
		Update("created_at", since.Add(-time.Hour)).Error; err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}

	counts, err := repo.CountByStatusSince(since)
	if err != nil {
		t.Fatalf("CountByStatusSince() error = %v", err)
	}
	if counts[model.HardeningTaskStatusCompleted] != 1 {
		t.Fatalf("completed count = %d, want 1 (found: %+v)", counts[model.HardeningTaskStatusCompleted], counts)
	}
	if counts[model.HardeningTaskStatusFailed] != 1 {
		t.Fatalf("failed count = %d, want 1 (found: %+v)", counts[model.HardeningTaskStatusFailed], counts)
	}
	if counts[model.HardeningTaskStatusQueued] != 0 {
		t.Fatalf("queued count = %d, want 0 (backdated task must be excluded): %+v", counts[model.HardeningTaskStatusQueued], counts)
	}
}

func TestHardeningRepository_HourlyCountsSinceBucketsByHourOfDay(t *testing.T) {
	repo, appRepo, database, scope := setupHardeningRepo(t)
	since := time.Now()

	app := createRepoApp(t, appRepo, scope, "hourly")
	task := newRepoTask(scope, "hourly", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}

	fixedHour := time.Date(since.Year(), since.Month(), since.Day(), 5, 30, 0, 0, since.Location())
	if fixedHour.Before(since) {
		fixedHour = fixedHour.Add(24 * time.Hour)
	}
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", task.ID).
		Update("created_at", fixedHour).Error; err != nil {
		t.Fatalf("set created_at: %v", err)
	}

	counts, err := repo.HourlyCountsSince(since)
	if err != nil {
		t.Fatalf("HourlyCountsSince() error = %v", err)
	}
	if counts[5] != 1 {
		t.Fatalf("counts[5] = %d, want 1: %+v", counts[5], counts)
	}
	total := int64(0)
	for _, c := range counts {
		total += c
	}
	if total != 1 {
		t.Fatalf("total hourly count = %d, want 1: %+v", total, counts)
	}
}

func TestHardeningRepository_AverageCompletedDurationSinceComputesExactAverage(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	since := time.Now()

	app := createRepoApp(t, appRepo, scope, "avg-duration")
	task := newRepoTask(scope, "avg-duration", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}

	startedAt := since.Add(time.Second)
	finishedAt := startedAt.Add(125 * time.Second)
	if err := repo.MarkTaskRunning(task.ID, startedAt); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := repo.CompleteTaskForApp(task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", finishedAt, model.RiskLevelLow); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	avgSeconds, ok, err := repo.AverageCompletedDurationSince(since)
	if err != nil {
		t.Fatalf("AverageCompletedDurationSince() error = %v", err)
	}
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if avgSeconds != 125 {
		t.Fatalf("avgSeconds = %v, want 125", avgSeconds)
	}
}

func TestHardeningRepository_AverageCompletedDurationSinceReturnsNotOkWhenNoneCompleted(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	since := time.Now()

	app := createRepoApp(t, appRepo, scope, "avg-duration-empty")
	task := newRepoTask(scope, "avg-duration-empty", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}

	avgSeconds, ok, err := repo.AverageCompletedDurationSince(since)
	if err != nil {
		t.Fatalf("AverageCompletedDurationSince() error = %v", err)
	}
	if ok {
		t.Fatalf("ok = true, want false (no completed tasks since cutoff)")
	}
	if avgSeconds != 0 {
		t.Fatalf("avgSeconds = %v, want 0", avgSeconds)
	}
}

func TestHardeningRepository_QueueCountIncludesQueuedAndRunning(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)

	before, err := repo.QueueCount()
	if err != nil {
		t.Fatalf("QueueCount() before error = %v", err)
	}

	queuedApp := createRepoApp(t, appRepo, scope, "queue-queued")
	queuedTask := newRepoTask(scope, "queue-queued", queuedApp.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&queuedTask); err != nil {
		t.Fatalf("CreateTaskWithSteps() queued error = %v", err)
	}

	runningApp := createRepoApp(t, appRepo, scope, "queue-running")
	runningTask := newRepoTask(scope, "queue-running", runningApp.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&runningTask); err != nil {
		t.Fatalf("CreateTaskWithSteps() running error = %v", err)
	}
	if err := repo.MarkTaskRunning(runningTask.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}

	after, err := repo.QueueCount()
	if err != nil {
		t.Fatalf("QueueCount() after error = %v", err)
	}
	if after-before != 2 {
		t.Fatalf("QueueCount() delta = %d, want 2 (before=%d after=%d)", after-before, before, after)
	}
}

func TestHardeningRepository_RecentReturnsMostRecentTasksGlobally(t *testing.T) {
	repo, appRepo, database, scope := setupHardeningRepo(t)

	appA := createRepoApp(t, appRepo, scope, "recent-a")
	taskA := newRepoTask(scope, "recent-a", appA.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&taskA); err != nil {
		t.Fatalf("CreateTaskWithSteps() A error = %v", err)
	}

	appB := createRepoApp(t, appRepo, scope, "recent-b")
	taskB := newRepoTask(scope, "recent-b", appB.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&taskB); err != nil {
		t.Fatalf("CreateTaskWithSteps() B error = %v", err)
	}

	future := time.Now().Add(24 * time.Hour)
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", taskA.ID).
		Update("created_at", future).Error; err != nil {
		t.Fatalf("set created_at A: %v", err)
	}
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", taskB.ID).
		Update("created_at", future.Add(time.Second)).Error; err != nil {
		t.Fatalf("set created_at B: %v", err)
	}

	recent, err := repo.Recent(2)
	if err != nil {
		t.Fatalf("Recent() error = %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("len(recent) = %d, want 2", len(recent))
	}
	if recent[0].ID != taskB.ID {
		t.Fatalf("recent[0].ID = %d, want %d (most recently created first)", recent[0].ID, taskB.ID)
	}
	if recent[1].ID != taskA.ID {
		t.Fatalf("recent[1].ID = %d, want %d", recent[1].ID, taskA.ID)
	}
	if recent[0].App.PackageName != appB.PackageName {
		t.Fatalf(`recent[0].App.PackageName = %q, want %q (Preload("App") must populate)`, recent[0].App.PackageName, appB.PackageName)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/repository/... -run 'CountByStatusSince|HourlyCountsSince|AverageCompletedDurationSince|QueueCountIncludes|RecentReturnsMostRecent' -v`
Expected: FAIL — compile error, all five methods undefined.

- [ ] **Step 3: Implement the five methods**

Add to `internal/repository/hardening_repository.go` (anywhere after `RecentByApp`, before `Steps`):

```go
func (r *HardeningRepository) CountByStatusSince(since time.Time) (map[model.HardeningTaskStatus]int64, error) {
	var statuses []model.HardeningTaskStatus
	if err := r.db.Model(&model.HardeningTask{}).
		Where("created_at >= ?", since).
		Pluck("status", &statuses).Error; err != nil {
		return nil, err
	}

	counts := make(map[model.HardeningTaskStatus]int64, 4)
	for _, status := range statuses {
		counts[status]++
	}
	return counts, nil
}

func (r *HardeningRepository) HourlyCountsSince(since time.Time) ([24]int64, error) {
	var counts [24]int64

	var createdAts []time.Time
	if err := r.db.Model(&model.HardeningTask{}).
		Where("created_at >= ?", since).
		Pluck("created_at", &createdAts).Error; err != nil {
		return counts, err
	}

	for _, createdAt := range createdAts {
		counts[createdAt.Local().Hour()]++
	}
	return counts, nil
}

type hardeningTaskDurationWindow struct {
	StartedAt  time.Time
	FinishedAt time.Time
}

func (r *HardeningRepository) AverageCompletedDurationSince(since time.Time) (avgSeconds float64, ok bool, err error) {
	var windows []hardeningTaskDurationWindow
	if err := r.db.Model(&model.HardeningTask{}).
		Select("started_at, finished_at").
		Where("created_at >= ? AND status = ? AND started_at IS NOT NULL AND finished_at IS NOT NULL", since, model.HardeningTaskStatusCompleted).
		Find(&windows).Error; err != nil {
		return 0, false, err
	}
	if len(windows) == 0 {
		return 0, false, nil
	}

	var total float64
	for _, w := range windows {
		total += w.FinishedAt.Sub(w.StartedAt).Seconds()
	}
	return total / float64(len(windows)), true, nil
}

func (r *HardeningRepository) QueueCount() (int64, error) {
	var count int64
	err := r.db.Model(&model.HardeningTask{}).
		Where("status IN ?", []model.HardeningTaskStatus{
			model.HardeningTaskStatusQueued,
			model.HardeningTaskStatusRunning,
		}).
		Count(&count).Error
	return count, err
}

func (r *HardeningRepository) Recent(limit int) ([]model.HardeningTask, error) {
	if limit < 1 {
		limit = 5
	}

	var tasks []model.HardeningTask
	err := r.db.Preload("App").
		Order("created_at DESC, id DESC").
		Limit(limit).
		Find(&tasks).Error
	return tasks, err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/repository/... -run 'CountByStatusSince|HourlyCountsSince|AverageCompletedDurationSince|QueueCountIncludes|RecentReturnsMostRecent' -v`
Expected: PASS for all 6 new tests.

Then run the whole package to check for regressions:

Run: `go test ./internal/repository/... -v 2>&1 | tail -40`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/repository/hardening_repository.go internal/repository/hardening_repository_test.go
git commit -m "feat: add dashboard aggregation queries to HardeningRepository"
```

---

### Task 4: `AppRepository.TopByRiskLevel`

**Files:**
- Modify: `internal/repository/app_repository.go`
- Modify: `internal/repository/app_repository_test.go`

**Interfaces:**
- Produces: `AppRepository.TopByRiskLevel(limit int) ([]model.App, error)` — consumed by Task 5 (`DashboardService`).

- [ ] **Step 1: Write the failing test**

Append to `internal/repository/app_repository_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repository/... -run TestAppRepository_TopByRiskLevelOrdersBySeverity -v`
Expected: FAIL — `undefined: repo.TopByRiskLevel`.

- [ ] **Step 3: Implement `TopByRiskLevel`**

Add to `internal/repository/app_repository.go`, after `UpdateStatus`:

```go
func (r *AppRepository) TopByRiskLevel(limit int) ([]model.App, error) {
	if limit < 1 {
		limit = 5
	}

	var apps []model.App
	err := r.db.
		Where("risk_level IS NOT NULL").
		Order(`CASE risk_level
			WHEN 'critical' THEN 4
			WHEN 'high' THEN 3
			WHEN 'medium' THEN 2
			WHEN 'low' THEN 1
			ELSE 0
		END DESC, updated_at DESC`).
		Limit(limit).
		Find(&apps).Error
	return apps, err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repository/... -run TestAppRepository_TopByRiskLevelOrdersBySeverity -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repository/app_repository.go internal/repository/app_repository_test.go
git commit -m "feat: add AppRepository.TopByRiskLevel"
```

---

### Task 5: `DashboardService`

**Files:**
- Create: `internal/service/dashboard_service.go`
- Create: `internal/service/dashboard_service_test.go`

**Interfaces:**
- Consumes: `HardeningRepository.CountByStatusSince/HourlyCountsSince/AverageCompletedDurationSince/QueueCount/Recent` (Task 3), `AppRepository.TopByRiskLevel` (Task 4), `HardeningRepository.CompleteTaskForApp` (Task 2, used only by the test).
- Produces: `service.DashboardOverview`, `service.HourlyPoint`, `service.ResultDistribution`, `service.DashboardTaskItem`, `service.DashboardRiskApp`, `service.DashboardSystemStatus`, `service.NewDashboardService(hardeningRepo *repository.HardeningRepository, appRepo *repository.AppRepository, engineVersion string) *DashboardService`, `(*DashboardService).GetOverview() (*DashboardOverview, error)` — consumed by Task 6 (handler).

- [ ] **Step 1: Write the failing test**

Create `internal/service/dashboard_service_test.go`:

```go
package service_test

import (
	"context"
	"testing"
	"time"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/service"
)

func TestDashboardService_GetOverviewReflectsNewCompletedTaskAndRiskApp(t *testing.T) {
	svc, appRepo, hardeningRepo, _, scope, _ := setupHardeningServiceTestWithAuditAndDB(t)
	dashboardSvc := service.NewDashboardService(hardeningRepo, appRepo, "BeetleShield Engine v2.4.1")

	before, err := dashboardSvc.GetOverview()
	if err != nil {
		t.Fatalf("GetOverview() before error = %v", err)
	}

	app := createHardeningServiceApp(t, appRepo, scope, "overview")
	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	startedAt := time.Now()
	finishedAt := startedAt.Add(125 * time.Second)
	if err := hardeningRepo.MarkTaskRunning(detail.Task.ID, startedAt); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := hardeningRepo.CompleteTaskForApp(detail.Task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", finishedAt, model.RiskLevelCritical); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	after, err := dashboardSvc.GetOverview()
	if err != nil {
		t.Fatalf("GetOverview() after error = %v", err)
	}

	if after.ResultDistribution.Success-before.ResultDistribution.Success != 1 {
		t.Fatalf("ResultDistribution.Success delta = %d, want 1 (before=%+v after=%+v)",
			after.ResultDistribution.Success-before.ResultDistribution.Success, before.ResultDistribution, after.ResultDistribution)
	}
	if after.TodayTaskCount-before.TodayTaskCount != 1 {
		t.Fatalf("TodayTaskCount delta = %d, want 1", after.TodayTaskCount-before.TodayTaskCount)
	}

	if len(after.RecentTasks) == 0 || after.RecentTasks[0].TaskNo != detail.Task.TaskNo {
		t.Fatalf("RecentTasks[0] = %+v, want TaskNo %q first (just-created task must sort first)", after.RecentTasks, detail.Task.TaskNo)
	}
	if after.RecentTasks[0].DurationSeconds == nil || *after.RecentTasks[0].DurationSeconds != 125 {
		t.Fatalf("RecentTasks[0].DurationSeconds = %v, want 125", after.RecentTasks[0].DurationSeconds)
	}

	if len(after.RiskTop5) == 0 || after.RiskTop5[0].PackageName != app.PackageName {
		t.Fatalf("RiskTop5[0] = %+v, want PackageName %q first (critical risk level must rank first)", after.RiskTop5, app.PackageName)
	}
	if after.RiskTop5[0].DisplayScore != 90 {
		t.Fatalf("RiskTop5[0].DisplayScore = %d, want 90 (critical mapping)", after.RiskTop5[0].DisplayScore)
	}

	if after.SystemStatus.EngineVersion != "BeetleShield Engine v2.4.1" {
		t.Fatalf("SystemStatus.EngineVersion = %q", after.SystemStatus.EngineVersion)
	}
	if len(after.HourlyTrend) != 24 {
		t.Fatalf("len(HourlyTrend) = %d, want 24", len(after.HourlyTrend))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -run TestDashboardService_GetOverview -v`
Expected: FAIL — `undefined: service.NewDashboardService` (package doesn't compile).

- [ ] **Step 3: Implement `dashboard_service.go`**

Create `internal/service/dashboard_service.go`:

```go
package service

import (
	"fmt"
	"math"
	"time"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type HourlyPoint struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

type ResultDistribution struct {
	Success    int `json:"success"`
	Failed     int `json:"failed"`
	Processing int `json:"processing"`
}

type DashboardTaskItem struct {
	TaskID          uint                      `json:"taskId"`
	TaskNo          string                    `json:"taskNo"`
	AppName         string                    `json:"appName"`
	PackageName     string                    `json:"packageName"`
	Version         string                    `json:"version"`
	Status          model.HardeningTaskStatus `json:"status"`
	DurationSeconds *int                      `json:"durationSeconds"`
	CreatedAt       time.Time                 `json:"createdAt"`
}

type DashboardRiskApp struct {
	AppID        uint            `json:"appId"`
	Name         string          `json:"name"`
	PackageName  string          `json:"packageName"`
	RiskLevel    model.RiskLevel `json:"riskLevel"`
	DisplayScore int             `json:"displayScore"`
}

type DashboardSystemStatus struct {
	EngineVersion string `json:"engineVersion"`
	QueueCount    int    `json:"queueCount"`
}

type DashboardOverview struct {
	TodayTaskCount     int                   `json:"todayTaskCount"`
	SuccessRate        float64               `json:"successRate"`
	AvgDurationSeconds int                   `json:"avgDurationSeconds"`
	QueueCount         int                   `json:"queueCount"`
	HourlyTrend        []HourlyPoint         `json:"hourlyTrend"`
	ResultDistribution ResultDistribution    `json:"resultDistribution"`
	RecentTasks        []DashboardTaskItem   `json:"recentTasks"`
	RiskTop5           []DashboardRiskApp    `json:"riskTop5"`
	SystemStatus       DashboardSystemStatus `json:"systemStatus"`
}

// riskLevelDisplayScore maps the 4-level RiskLevel enum to a fixed display
// score for the Top5 progress bars. This is not a precise numeric score
// (App never stores one) — it only needs to render in the right relative
// order and magnitude.
var riskLevelDisplayScore = map[model.RiskLevel]int{
	model.RiskLevelCritical: 90,
	model.RiskLevelHigh:     65,
	model.RiskLevelMedium:   40,
	model.RiskLevelLow:      15,
}

type DashboardService struct {
	hardeningRepo *repository.HardeningRepository
	appRepo       *repository.AppRepository
	engineVersion string
}

func NewDashboardService(hardeningRepo *repository.HardeningRepository, appRepo *repository.AppRepository, engineVersion string) *DashboardService {
	return &DashboardService{
		hardeningRepo: hardeningRepo,
		appRepo:       appRepo,
		engineVersion: engineVersion,
	}
}

// GetOverview is a read-only aggregation: it never writes to the database,
// and "today" is always the caller's local calendar day at the moment of
// the call.
func (s *DashboardService) GetOverview() (*DashboardOverview, error) {
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	statusCounts, err := s.hardeningRepo.CountByStatusSince(startOfDay)
	if err != nil {
		return nil, err
	}
	hourly, err := s.hardeningRepo.HourlyCountsSince(startOfDay)
	if err != nil {
		return nil, err
	}
	avgSeconds, hasAvg, err := s.hardeningRepo.AverageCompletedDurationSince(startOfDay)
	if err != nil {
		return nil, err
	}
	queueCount, err := s.hardeningRepo.QueueCount()
	if err != nil {
		return nil, err
	}
	recentTasks, err := s.hardeningRepo.Recent(7)
	if err != nil {
		return nil, err
	}
	riskApps, err := s.appRepo.TopByRiskLevel(5)
	if err != nil {
		return nil, err
	}

	completed := int(statusCounts[model.HardeningTaskStatusCompleted])
	failed := int(statusCounts[model.HardeningTaskStatusFailed])
	queued := int(statusCounts[model.HardeningTaskStatusQueued])
	running := int(statusCounts[model.HardeningTaskStatusRunning])

	var successRate float64
	if completed+failed > 0 {
		successRate = float64(completed) / float64(completed+failed) * 100
	}

	avgDuration := 0
	if hasAvg {
		avgDuration = int(math.Round(avgSeconds))
	}

	hourlyTrend := make([]HourlyPoint, 24)
	for h := 0; h < 24; h++ {
		hourlyTrend[h] = HourlyPoint{Hour: fmt.Sprintf("%02d:00", h), Count: int(hourly[h])}
	}

	taskItems := make([]DashboardTaskItem, 0, len(recentTasks))
	for _, task := range recentTasks {
		item := DashboardTaskItem{
			TaskID:      task.ID,
			TaskNo:      task.TaskNo,
			AppName:     task.App.Name,
			PackageName: task.App.PackageName,
			Version:     task.App.Version,
			Status:      task.Status,
			CreatedAt:   task.CreatedAt,
		}
		if task.StartedAt != nil && task.FinishedAt != nil {
			seconds := int(task.FinishedAt.Sub(*task.StartedAt).Seconds())
			item.DurationSeconds = &seconds
		}
		taskItems = append(taskItems, item)
	}

	riskItems := make([]DashboardRiskApp, 0, len(riskApps))
	for _, app := range riskApps {
		if app.RiskLevel == nil {
			continue
		}
		riskItems = append(riskItems, DashboardRiskApp{
			AppID:        app.ID,
			Name:         app.Name,
			PackageName:  app.PackageName,
			RiskLevel:    *app.RiskLevel,
			DisplayScore: riskLevelDisplayScore[*app.RiskLevel],
		})
	}

	return &DashboardOverview{
		TodayTaskCount:     completed + failed + queued + running,
		SuccessRate:        successRate,
		AvgDurationSeconds: avgDuration,
		QueueCount:         int(queueCount),
		HourlyTrend:        hourlyTrend,
		ResultDistribution: ResultDistribution{
			Success:    completed,
			Failed:     failed,
			Processing: queued + running,
		},
		RecentTasks: taskItems,
		RiskTop5:    riskItems,
		SystemStatus: DashboardSystemStatus{
			EngineVersion: s.engineVersion,
			QueueCount:    int(queueCount),
		},
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/service/... -run TestDashboardService_GetOverview -v`
Expected: PASS.

Then run the whole package to check for regressions:

Run: `go test ./internal/service/... -v 2>&1 | tail -60`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/service/dashboard_service.go internal/service/dashboard_service_test.go
git commit -m "feat: add DashboardService.GetOverview"
```

---

### Task 6: HTTP endpoint — handler + router + `main.go`

**Files:**
- Modify: `internal/handler/hardening_handler.go`
- Modify: `internal/handler/hardening_handler_test.go`
- Modify: `internal/router/router.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `(*service.DashboardService).GetOverview` (Task 5).
- Produces: `(*HardeningHandler).GetOverview(c *gin.Context)`, route `GET /api/v1/hardening-tasks/overview`. `NewHardeningHandler` gains a 2nd parameter `dashboardSvc *service.DashboardService` — every call site must be updated (this task updates `cmd/server/main.go` and the handler test helper).

- [ ] **Step 1: Write the failing test**

In `internal/handler/hardening_handler_test.go`, update `setupHardeningRouter`'s handler construction:

Replace:

```go
	strategySvc := service.NewStrategyService(repository.NewStrategyRepository(database), auditService)
	hardeningRepo := repository.NewHardeningRepository(database)
	hardeningSvc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningHandlerURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		auditService,
		"BeetleShield Engine v2.4.1",
	)
	hardeningHandler := handler.NewHardeningHandler(hardeningSvc)
```

With:

```go
	strategySvc := service.NewStrategyService(repository.NewStrategyRepository(database), auditService)
	hardeningRepo := repository.NewHardeningRepository(database)
	hardeningSvc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningHandlerURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		auditService,
		"BeetleShield Engine v2.4.1",
	)
	dashboardSvc := service.NewDashboardService(hardeningRepo, appRepo, "BeetleShield Engine v2.4.1")
	hardeningHandler := handler.NewHardeningHandler(hardeningSvc, dashboardSvc)
```

Then append this test function (below `setupHardeningRouter`, alongside the other `TestHardeningHandler_*` functions):

```go
func TestHardeningHandler_GetOverviewReturnsAggregatedData(t *testing.T) {
	srv, _, developerToken, _, appID, _, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"appId": appID})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp.Body.Close()

	// Requesting the literal path "overview" also proves this route isn't
	// shadowed by GET /:id (which would otherwise fail to parse "overview"
	// as a uint and return 400, not 200).
	overviewReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/hardening-tasks/overview", nil)
	overviewReq.Header.Set("Authorization", "Bearer "+developerToken)
	overviewResp, err := http.DefaultClient.Do(overviewReq)
	if err != nil {
		t.Fatalf("overview request: %v", err)
	}
	defer overviewResp.Body.Close()
	if overviewResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", overviewResp.StatusCode, http.StatusOK)
	}

	var got struct {
		Data service.DashboardOverview `json:"data"`
	}
	if err := json.NewDecoder(overviewResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode overview response: %v", err)
	}
	if len(got.Data.HourlyTrend) != 24 {
		t.Fatalf("len(HourlyTrend) = %d, want 24", len(got.Data.HourlyTrend))
	}
	if got.Data.SystemStatus.EngineVersion != "BeetleShield Engine v2.4.1" {
		t.Fatalf("SystemStatus.EngineVersion = %q", got.Data.SystemStatus.EngineVersion)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/handler/... -run TestHardeningHandler_GetOverview -v`
Expected: FAIL — compile error (`handler.NewHardeningHandler` called with wrong number of args).

- [ ] **Step 3: Implement the handler, route, and `main.go` wiring**

In `internal/handler/hardening_handler.go`, replace the struct and constructor:

```go
type HardeningHandler struct {
	svc *service.HardeningService
}

func NewHardeningHandler(svc *service.HardeningService) *HardeningHandler {
	return &HardeningHandler{svc: svc}
}
```

With:

```go
type HardeningHandler struct {
	svc          *service.HardeningService
	dashboardSvc *service.DashboardService
}

func NewHardeningHandler(svc *service.HardeningService, dashboardSvc *service.DashboardService) *HardeningHandler {
	return &HardeningHandler{svc: svc, dashboardSvc: dashboardSvc}
}
```

Add this method after `AppHistory` (end of file, before `parseUintParam`):

```go
func (h *HardeningHandler) GetOverview(c *gin.Context) {
	overview, err := h.dashboardSvc.GetOverview()
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50024, "查询系统总览失败")
		return
	}

	response.Success(c, http.StatusOK, overview)
}
```

In `internal/router/router.go`, add the route inside the existing `hardeningTasks` group, **before** `/:id`:

```go
		hardeningTasks := v1.Group("/hardening-tasks")
		hardeningTasks.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			hardeningTasks.POST("", writeRoles, deps.HardeningHandler.Create)
			hardeningTasks.GET("", deps.HardeningHandler.List)
			hardeningTasks.GET("/overview", deps.HardeningHandler.GetOverview)
			hardeningTasks.GET("/:id", deps.HardeningHandler.Get)
			hardeningTasks.GET("/:id/logs", deps.HardeningHandler.Logs)
			hardeningTasks.GET("/:id/report", deps.HardeningHandler.GetReport)
			hardeningTasks.GET("/:id/download-url", writeRoles, deps.HardeningHandler.DownloadURL)
		}
```

In `cmd/server/main.go`, replace:

```go
	hardeningService := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategyService,
		storageClient,
		cfg.DPTDefaultVMPRules,
		auditService,
		cfg.HardeningEngineVersion,
	)
	hardeningHandler := handler.NewHardeningHandler(hardeningService)
```

With:

```go
	hardeningService := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategyService,
		storageClient,
		cfg.DPTDefaultVMPRules,
		auditService,
		cfg.HardeningEngineVersion,
	)
	dashboardService := service.NewDashboardService(hardeningRepo, appRepo, cfg.HardeningEngineVersion)
	hardeningHandler := handler.NewHardeningHandler(hardeningService, dashboardService)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/handler/... -run TestHardeningHandler_GetOverview -v`
Expected: PASS.

Then run the whole handler package to check for regressions:

Run: `go test ./internal/handler/... -v 2>&1 | tail -60`
Expected: `ok`.

- [ ] **Step 5: Build to verify `main.go` wiring compiles**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/handler/hardening_handler.go internal/handler/hardening_handler_test.go \
  internal/router/router.go cmd/server/main.go
git commit -m "feat: expose GET /hardening-tasks/overview endpoint"
```

---

### Task 7: Frontend types + API client

**Files:**
- Modify: `BeetleShieldFrontend/src/api/types.ts`
- Create: `BeetleShieldFrontend/src/api/dashboard.ts`

**Interfaces:**
- Produces: TS types `HourlyPoint`, `ResultDistribution`, `DashboardTaskItem`, `DashboardRiskApp`, `DashboardSystemStatus`, `DashboardOverview`; function `getDashboardOverview(): Promise<DashboardOverview>` — consumed by Task 8 (`Dashboard.tsx`).

This task has no automated test — matching the existing `hardening.ts`/`apps.ts` pattern (thin typed wrappers, no dedicated tests). Verification is via `npx tsc --noEmit`, plus manual browser verification in Task 8.

- [ ] **Step 1: Add types to `src/api/types.ts`**

Insert a new section right after the `// ---- Hardening` section's last export (`HardeningReport`, just before `// ---- Audit logs`):

```typescript
// ---- Dashboard -------------------------------------------------------------

export interface HourlyPoint {
  hour: string
  count: number
}

export interface ResultDistribution {
  success: number
  failed: number
  processing: number
}

export interface DashboardTaskItem {
  taskId: number
  taskNo: string
  appName: string
  packageName: string
  version: string
  status: HardeningTaskStatus
  durationSeconds: number | null
  createdAt: string
}

export interface DashboardRiskApp {
  appId: number
  name: string
  packageName: string
  riskLevel: RiskLevel
  displayScore: number
}

export interface DashboardSystemStatus {
  engineVersion: string
  queueCount: number
}

export interface DashboardOverview {
  todayTaskCount: number
  successRate: number
  avgDurationSeconds: number
  queueCount: number
  hourlyTrend: HourlyPoint[]
  resultDistribution: ResultDistribution
  recentTasks: DashboardTaskItem[]
  riskTop5: DashboardRiskApp[]
  systemStatus: DashboardSystemStatus
}
```

(`RiskLevel` and `HardeningTaskStatus` are already defined earlier in this same file — reuse them, do not redeclare.)

- [ ] **Step 2: Create `src/api/dashboard.ts`**

```typescript
import apiClient from './client'
import type { DashboardOverview } from './types'

export function getDashboardOverview(): Promise<DashboardOverview> {
  return apiClient.get('/hardening-tasks/overview') as unknown as Promise<DashboardOverview>
}
```

- [ ] **Step 3: Type-check**

Run (from `BeetleShieldFrontend/`): `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
cd /Users/yrighc/work/hzyz/project/BeetleShieldFrontend
git add src/api/types.ts src/api/dashboard.ts
git commit -m "feat: add dashboard overview API client"
```

---

### Task 8: `Dashboard.tsx` — replace mock data with real API

**Files:**
- Modify: `BeetleShieldFrontend/src/pages/Dashboard.tsx`

**Interfaces:**
- Consumes: `getDashboardOverview` (Task 7).

- [ ] **Step 1: Replace the entire file**

The mock data (`hourlyData`, `pieData`, `recentTasks` array, `riskApps` array), the 4-card trend badges, and the "工作节点" system-status card are all removed. `TaskRecord`, `MetricCard`, `SystemStatusCard`, `StatusBadge`, `columns`, `riskLevelConfig`, `statusConfig`, and the chart configs are kept (adapted to read from the fetched `overview` instead of module-level constants), since they are pure presentation and match the design's "keep presentation code, swap data source" approach used in `Reports.tsx`.

Replace the full contents of `src/pages/Dashboard.tsx` with:

```tsx
import { useEffect, useState } from 'react'
import { Row, Col, Table, Tag, Button, Tooltip, Progress, Typography, Spin, Empty, message } from 'antd'
import {
  ClockCircleOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  SyncOutlined,
  EllipsisOutlined,
  ReloadOutlined,
  EyeOutlined,
} from '@ant-design/icons'
import { Line, Pie } from '@ant-design/charts'
import type { ColumnsType } from 'antd/es/table'
import { getDashboardOverview } from '../api/dashboard'
import type { DashboardOverview, HardeningTaskStatus, RiskLevel } from '../api/types'

const { Text } = Typography

/* ================================================================
   类型 & 工具函数
   ================================================================ */
interface TaskRecord {
  key: string
  taskId: string
  appName: string
  packageName: string
  version: string
  status: 'success' | 'error' | 'processing' | 'pending'
  duration: string
  time: string
}

function toDisplayStatus(status: HardeningTaskStatus): TaskRecord['status'] {
  switch (status) {
    case 'completed':
      return 'success'
    case 'failed':
      return 'error'
    case 'running':
      return 'processing'
    default:
      return 'pending'
  }
}

function formatDuration(seconds: number | null, status: HardeningTaskStatus): string {
  if (seconds != null) {
    const m = Math.floor(seconds / 60)
    const s = seconds % 60
    return `${m}分${s}秒`
  }
  return status === 'running' ? '进行中...' : '等待中'
}

function formatMinutesSeconds(totalSeconds: number): string {
  const m = Math.floor(totalSeconds / 60)
  const s = totalSeconds % 60
  return `${m}分${s}秒`
}

function formatSubmitTime(iso: string): string {
  const d = new Date(iso)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

function toRiskLevelConfigKey(level: RiskLevel): 'high' | 'medium' | 'low' {
  return level === 'critical' ? 'high' : level
}

const statusConfig = {
  success:    { label: '成功',  color: '#4ade80', bg: 'rgba(74,222,128,0.12)',  border: 'rgba(74,222,128,0.3)',  icon: <CheckCircleOutlined /> },
  error:      { label: '失败',  color: '#f87171', bg: 'rgba(248,113,113,0.12)', border: 'rgba(248,113,113,0.3)', icon: <ExclamationCircleOutlined /> },
  processing: { label: '进行中', color: '#adc6ff', bg: 'rgba(173,198,255,0.12)', border: 'rgba(173,198,255,0.3)', icon: <SyncOutlined spin /> },
  pending:    { label: '等待中', color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.25)', icon: <ClockCircleOutlined /> },
}

const riskLevelConfig = {
  high:   { color: '#f87171', label: '高风险' },
  medium: { color: '#fbbf24', label: '中风险' },
  low:    { color: '#4ade80', label: '低风险' },
}

function StatusBadge({ status }: { status: TaskRecord['status'] }) {
  const cfg = statusConfig[status]
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        padding: '2px 10px',
        borderRadius: 20,
        fontSize: 12,
        fontWeight: 500,
        color: cfg.color,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        whiteSpace: 'nowrap',
      }}
    >
      {cfg.icon}
      {cfg.label}
    </span>
  )
}

/* ================================================================
   表格列定义
   ================================================================ */
const columns: ColumnsType<TaskRecord> = [
  {
    title: '任务ID',
    dataIndex: 'taskId',
    width: 140,
    render: (v: string) => (
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-text-muted)' }}>
        {v}
      </span>
    ),
  },
  {
    title: '应用名称',
    dataIndex: 'appName',
    render: (name: string, row: TaskRecord) => (
      <div>
        <div style={{ fontWeight: 500, color: 'var(--color-text-primary)', fontSize: 13 }}>{name}</div>
        <div style={{ fontSize: 11, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>{row.packageName}</div>
      </div>
    ),
  },
  {
    title: '版本',
    dataIndex: 'version',
    width: 80,
    render: (v: string) => (
      <Tag
        style={{
          background: 'rgba(173,198,255,0.08)',
          border: '1px solid rgba(173,198,255,0.2)',
          color: 'var(--color-primary)',
          borderRadius: 20,
          fontSize: 11,
        }}
      >
        v{v}
      </Tag>
    ),
  },
  {
    title: '状态',
    dataIndex: 'status',
    width: 90,
    render: (s: TaskRecord['status']) => <StatusBadge status={s} />,
  },
  {
    title: '耗时',
    dataIndex: 'duration',
    width: 90,
    render: (d: string) => (
      <span style={{ fontSize: 12, color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
        {d}
      </span>
    ),
  },
  {
    title: '提交时间',
    dataIndex: 'time',
    width: 80,
    render: (t: string) => (
      <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>今日 {t}</span>
    ),
  },
  {
    title: '操作',
    width: 80,
    render: () => (
      <div style={{ display: 'flex', gap: 4 }}>
        <Tooltip title="查看详情">
          <Button
            type="text"
            size="small"
            icon={<EyeOutlined />}
            style={{ color: 'var(--color-text-muted)' }}
          />
        </Tooltip>
        <Tooltip title="更多">
          <Button
            type="text"
            size="small"
            icon={<EllipsisOutlined />}
            style={{ color: 'var(--color-text-muted)' }}
          />
        </Tooltip>
      </div>
    ),
  },
]

/* ================================================================
   子组件：统计卡片
   ================================================================ */
interface MetricCardProps {
  icon: string
  iconBg: string
  value: string
  label: string
  animDelay?: string
}

function MetricCard({ icon, iconBg, value, label, animDelay = '0s' }: MetricCardProps) {
  return (
    <div
      className="metric-card fade-in-up"
      style={{ animationDelay: animDelay, height: '100%' }}
    >
      <div
        className="metric-icon"
        style={{ background: iconBg, fontSize: 20 }}
      >
        {icon}
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  )
}

/* ================================================================
   子组件：系统状态卡片
   ================================================================ */
function SystemStatusCard({ icon, title, value }: { icon: string; title: string; value: string }) {
  return (
    <div
      style={{
        background: 'var(--color-surface-overlay)',
        border: '1px solid var(--color-border-subtle)',
        borderRadius: 'var(--radius-md)',
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'center',
        gap: 14,
      }}
    >
      <div
        style={{
          width: 40,
          height: 40,
          borderRadius: 10,
          background: 'var(--color-surface-container)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 20,
        }}
      >
        {icon}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 2 }}>{title}</div>
        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>{value}</div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
        <div
          style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: '#4ade80',
            boxShadow: '0 0 8px rgba(74,222,128,0.4)',
            animation: 'pulse-online 2.5s infinite',
          }}
        />
        <span style={{ fontSize: 12, color: '#4ade80', fontWeight: 500 }}>运行中</span>
      </div>
    </div>
  )
}

/* ================================================================
   主组件：Dashboard
   ================================================================ */
export default function Dashboard() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null)
  const [loading, setLoading] = useState(false)

  const load = () => {
    setLoading(true)
    getDashboardOverview()
      .then((data) => setOverview(data))
      .catch(() => {
        message.error('加载系统总览失败')
        setOverview(null)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  const taskRows: TaskRecord[] = (overview?.recentTasks ?? []).map((t) => ({
    key: String(t.taskId),
    taskId: t.taskNo,
    appName: t.appName,
    packageName: t.packageName,
    version: t.version,
    status: toDisplayStatus(t.status),
    duration: formatDuration(t.durationSeconds, t.status),
    time: formatSubmitTime(t.createdAt),
  }))

  const riskRows = (overview?.riskTop5 ?? []).map((r) => ({
    name: r.name,
    pkg: r.packageName,
    risk: r.displayScore,
    level: toRiskLevelConfigKey(r.riskLevel),
  }))

  const pieData = overview
    ? [
        { type: '成功', value: overview.resultDistribution.success },
        { type: '失败', value: overview.resultDistribution.failed },
        { type: '进行中', value: overview.resultDistribution.processing },
      ]
    : []

  /* 折线图配置 */
  const lineConfig = {
    data: overview?.hourlyTrend ?? [],
    xField: 'hour',
    yField: 'count',
    smooth: true,
    height: 220,
    autoFit: true,
    style: {
      stroke: '#adc6ff',
      lineWidth: 2,
    },
    area: {
      style: {
        fill: 'l(270) 0:rgba(173,198,255,0) 1:rgba(173,198,255,0.15)',
      },
    },
    point: { shapeField: 'circle', sizeField: 3, style: { fill: '#adc6ff', stroke: '#0b1326', lineWidth: 2 } },
    axis: {
      x: {
        label: { style: { fill: '#7b8199', fontSize: 11 } },
        line: { style: { stroke: '#2a3147' } },
        tick: false,
      },
      y: {
        label: { style: { fill: '#7b8199', fontSize: 11 } },
        gridLine: { style: { stroke: '#1a2236', lineDash: [4, 4] } },
      },
    },
    tooltip: {
      domStyles: {
        'g2-tooltip': {
          background: '#222a3d',
          border: '1px solid #424754',
          borderRadius: '8px',
          color: '#dae2fd',
          boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
        },
      },
    },
    theme: 'dark',
    background: 'transparent',
  }

  /* 饼图配置 */
  const pieConfig = {
    data: pieData,
    angleField: 'value',
    colorField: 'type',
    height: 220,
    autoFit: true,
    color: ['#4ade80', '#f87171', '#fbbf24'],
    innerRadius: 0.6,
    label: {
      text: (d: { type: string; value: number }) => `${d.type}: ${d.value}`,
      style: { fill: '#c2c6d6', fontSize: 12 },
    },
    legend: {
      color: {
        position: 'bottom',
        itemLabelFill: '#c2c6d6',
        itemLabelFontSize: 12,
      },
    },
    tooltip: {
      items: [
        { channel: 'y', name: '数量', valueFormatter: (v: number) => `${v} 个` },
      ],
    },
    statistic: {
      title: { style: { color: '#7b8199', fontSize: 12 }, content: '总任务' },
      content: {
        style: { color: '#dae2fd', fontSize: 22, fontWeight: 700 },
        content: String(overview?.todayTaskCount ?? 0),
      },
    },
    theme: 'dark',
    background: 'transparent',
    interactions: [{ type: 'element-active' }],
  }

  const cardStyle = {
    background: 'var(--color-surface-container)',
    border: '1px solid var(--color-border-subtle)',
    borderRadius: 12,
    padding: '20px',
  }

  const cardTitleStyle = {
    fontSize: 15,
    fontWeight: 600,
    color: 'var(--color-text-primary)',
    marginBottom: 16,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between' as const,
  }

  return (
    <div style={{ padding: 24, minHeight: '100%' }}>

      {/* ── 页面标题 ── */}
      <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
            系统总览
          </h1>
          <p style={{ fontSize: 13, color: 'var(--color-text-muted)', marginTop: 4 }}>
            {new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' })} · 今日数据
          </p>
        </div>
        <Button
          icon={<ReloadOutlined />}
          style={{
            background: 'var(--color-surface-container)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text-secondary)',
            borderRadius: 8,
          }}
          onClick={load}
        >
          刷新
        </Button>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <Spin size="large" />
        </div>
      )}

      {!loading && !overview && (
        <Empty description="加载系统总览失败，请点击刷新重试" style={{ padding: '80px 0' }} />
      )}

      {!loading && overview && (
        <>
          {/* ── 第一行：4 个统计卡片 ── */}
          <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
            <Col xs={24} sm={12} lg={6}>
              <MetricCard
                icon="🔧"
                iconBg="rgba(173,198,255,0.12)"
                value={String(overview.todayTaskCount)}
                label="今日加固任务"
                animDelay="0.05s"
              />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <MetricCard
                icon="✅"
                iconBg="rgba(74,222,128,0.12)"
                value={`${overview.successRate.toFixed(1)}%`}
                label="成功率"
                animDelay="0.1s"
              />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <MetricCard
                icon="⏱️"
                iconBg="rgba(251,191,36,0.1)"
                value={formatMinutesSeconds(overview.avgDurationSeconds)}
                label="平均加固耗时"
                animDelay="0.15s"
              />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <MetricCard
                icon="📋"
                iconBg="rgba(96,165,250,0.1)"
                value={String(overview.queueCount)}
                label="队列中任务"
                animDelay="0.2s"
              />
            </Col>
          </Row>

          {/* ── 第二行：折线图 + 饼图 ── */}
          <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
            <Col xs={24} lg={15}>
              <div style={cardStyle}>
                <div style={cardTitleStyle}>
                  <span>今日加固任务趋势</span>
                  <Text style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 400 }}>
                    最近 24 小时
                  </Text>
                </div>
                <Line {...lineConfig} />
              </div>
            </Col>
            <Col xs={24} lg={9}>
              <div style={{ ...cardStyle, height: '100%' }}>
                <div style={cardTitleStyle}>
                  <span>加固结果分布</span>
                  <Text style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 400 }}>
                    今日
                  </Text>
                </div>
                <Pie {...pieConfig} />
              </div>
            </Col>
          </Row>

          {/* ── 第三行：任务表格 + 风险应用 Top5 ── */}
          <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
            <Col xs={24} lg={15}>
              <div style={cardStyle}>
                <div style={cardTitleStyle}>
                  <span>最近加固任务</span>
                </div>
                <Table<TaskRecord>
                  columns={columns}
                  dataSource={taskRows}
                  pagination={false}
                  size="small"
                  style={{ background: 'transparent' }}
                  scroll={{ x: 700 }}
                  locale={{ emptyText: '暂无加固任务' }}
                />
              </div>
            </Col>

            <Col xs={24} lg={9}>
              <div style={{ ...cardStyle, height: '100%' }}>
                <div style={cardTitleStyle}>
                  <span>风险应用 Top 5</span>
                  <Text style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 400 }}>
                    按风险等级排序
                  </Text>
                </div>
                {riskRows.length === 0 ? (
                  <Empty description="暂无风险数据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    {riskRows.map((app, idx) => {
                      const lvl = riskLevelConfig[app.level]
                      return (
                        <div key={app.pkg}>
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              marginBottom: 6,
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span
                                style={{
                                  width: 20,
                                  height: 20,
                                  borderRadius: '50%',
                                  background: 'var(--color-surface-elevated)',
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'center',
                                  fontSize: 11,
                                  fontWeight: 700,
                                  color: 'var(--color-text-muted)',
                                  flexShrink: 0,
                                }}
                              >
                                {idx + 1}
                              </span>
                              <div>
                                <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--color-text-primary)', lineHeight: 1.3 }}>
                                  {app.name}
                                </div>
                                <div style={{ fontSize: 11, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                                  {app.pkg}
                                </div>
                              </div>
                            </div>
                            <div style={{ textAlign: 'right', flexShrink: 0 }}>
                              <div style={{ fontSize: 12, fontWeight: 600, color: lvl.color, marginBottom: 2 }}>
                                {app.risk} 分
                              </div>
                            </div>
                          </div>
                          <Progress
                            percent={app.risk}
                            showInfo={false}
                            size={['100%', 4]}
                            strokeColor={{ from: lvl.color, to: lvl.color + '88' }}
                            railColor="var(--color-surface-elevated)"
                          />
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            </Col>
          </Row>

          {/* ── 第四行：系统状态 ── */}
          <div style={cardStyle}>
            <div style={{ ...cardTitleStyle, marginBottom: 14 }}>
              <span>系统状态</span>
              <span
                style={{
                  fontSize: 12,
                  color: 'var(--color-success)',
                  background: 'rgba(74,222,128,0.1)',
                  border: '1px solid rgba(74,222,128,0.2)',
                  padding: '2px 10px',
                  borderRadius: 20,
                  fontWeight: 500,
                }}
              >
                全部正常
              </span>
            </div>
            <Row gutter={[12, 12]}>
              <Col xs={24} sm={12} lg={8}>
                <SystemStatusCard icon="⚙️" title="加固引擎" value="运行中" />
              </Col>
              <Col xs={24} sm={12} lg={8}>
                <SystemStatusCard icon="📋" title="任务队列" value={`${overview.systemStatus.queueCount} 个任务`} />
              </Col>
              <Col xs={24} sm={12} lg={8}>
                <SystemStatusCard icon="🔬" title="引擎版本" value={overview.systemStatus.engineVersion} />
              </Col>
            </Row>
          </div>
        </>
      )}

    </div>
  )
}
```

- [ ] **Step 2: Type-check**

Run (from `BeetleShieldFrontend/`): `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Manual browser verification**

Start the backend (`make run` in `BeetleShieldBackend`) and frontend (`npm run dev` in `BeetleShieldFrontend`). Log in and open the "总览" (Dashboard) page:
- Confirm the 4 top cards show real numbers (no "较昨日" badges anymore).
- Confirm the 24h trend line chart and result-distribution pie chart render (not necessarily with visible non-zero data if the dev DB has no tasks created today — just confirm no crash and the empty/zero state looks reasonable).
- Confirm "最近加固任务" table shows real recent tasks (or "暂无加固任务" if none exist).
- Confirm "风险应用 Top 5" shows real apps with a `RiskLevel` set (or the "暂无风险数据" empty state if none have completed a hardening task since this feature shipped).
- Confirm "系统状态" shows exactly 3 cards (加固引擎/任务队列/引擎版本), no "工作节点" card.
- Click "刷新" and confirm the page re-fetches without errors (check browser console/network tab).

- [ ] **Step 4: Commit**

```bash
cd /Users/yrighc/work/hzyz/project/BeetleShieldFrontend
git add src/pages/Dashboard.tsx
git commit -m "feat: wire Dashboard page to real overview API"
```

---

### Task 9: Full backend regression run

**Files:** none (verification-only task)

**Interfaces:** none

- [ ] **Step 1: Run `go vet` and `gofmt` check**

Run: `go vet ./... && gofmt -l .`
Expected: no output from either command. If `gofmt -l .` lists files, run `gofmt -w <file>` on each and re-check.

- [ ] **Step 2: Run the full test suite**

Run: `go test ./... -v 2>&1 | tail -120`
Expected: `ok` for every package, in particular `internal/repository`, `internal/service`, `internal/handler`, and `internal/worker` (this is the first time `CompleteTaskForApp`'s new `riskLevel` parameter and `NewHardeningHandler`'s new `dashboardSvc` parameter are exercised end-to-end across every existing caller).

- [ ] **Step 3: Commit** (only if Step 1 required `gofmt -w` fixes; otherwise skip)

```bash
git add -A
git commit -m "chore: gofmt fixes from dashboard work"
```

---

## Post-plan note

This plan intentionally does not touch: numeric risk scores persisted on `App` (only the 4-level enum), historical multi-day trend comparisons, PDF/CSV export of dashboard data, or real multi-node worker health checks — all explicitly deferred or out of scope per the design doc.
