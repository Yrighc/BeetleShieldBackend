# BeetleShield Backend — Hardening Report Scoring (Sub-project 7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only, real-time-computed hardening report for completed tasks — overall risk index (before/after), 5 protection-dimension bar-chart data, a 6-item vulnerability checklist, and delivery-artifact info — exposed via `GET /api/v1/hardening-tasks/:id/report`, and wire the frontend's `Reports.tsx` (currently 100% mock data) to it.

**Architecture:** No new table, no new service dependency graph — the report is a pure function `(model.HardeningTask, engineVersion string) → HardeningReport` computed on read from the existing `HardeningTask.StrategySnapshot` + artifact fields (already preloaded with `App` by `HardeningRepository.FindByID`). A new `ResolveEffectiveFlags` helper becomes the single source of truth for "which `Strategy` fields actually turn into a `dpt.jar` flag," shared by both the existing `BuildDPTCommand` and the new scorer, so the two can never silently drift apart.

**Tech Stack:** Same as existing codebase — Go, Gin, GORM/Postgres, no new dependencies. Frontend: React + TypeScript + antd, existing `src/api/*.ts` axios-wrapper pattern.

Reference spec: [`docs/superpowers/specs/2026-07-03-backend-report-scoring-design.md`](../specs/2026-07-03-backend-report-scoring-design.md)

## Global Constraints

- Module name: `beetleshield-backend`. API prefix `/api/v1`; unified `{code,message,data}` envelope via `internal/pkg/response`.
- Local dev Postgres: `root`/`root`@`localhost:5432`/`beetleshield` (pre-existing `pg12-dev` container, per existing `*_test.go` `testConfig`-style setup). Shared DB is not pristine — scope test assertions with unique `runID`-prefixed package names / emails, not table-wide counts, matching every existing `internal/service/*_test.go` and `internal/handler/*_test.go` file.
- No database migration needed — no new table, no new column.
- `GET /api/v1/hardening-tasks/:id/report` is readable by any authenticated role (`JWTAuth` only, no `RequireRole`), matching the sibling `GET /api/v1/hardening-tasks/:id`.
- Report is computed only for `status == completed` tasks; any other status returns a new `409` business error, never a `500` or a report with garbage/zero artifact data.
- The 6 score categories (`反调试/环境检测`, `Hook/注入防御`, `签名校验`, `DEX 混淆`, `SO 加壳保护`, `资源/字符串加密`; weights 15/15/15/20/20/15 = 100) drive the overall `afterScore`. The frontend's 5-dimension bar chart merges the first two categories into a single "反调试保护" entry (combined weight 30); the other 4 categories map 1:1. Both facts come straight from the spec — do not invent a different weight split.
- `Strategy.Debugger` and `Strategy.SoShell` values `aes`/`custom_so` are known-dead fields (never translated into a real `dpt.jar` flag by `BuildDPTCommand`) — `ResolveEffectiveFlags` must not treat them as contributing to any score, per the spec's "已知的现有代码问题" section. Do not "fix" `BuildDPTCommand` to wire them up — that's explicitly out of scope.
- `App.RiskLevel *model.RiskLevel` (four values: `low`/`medium`/`high`/`critical`) already exists on the `App` model from sub-project 1 but has never been written anywhere. The report's `riskLevel` field reuses this exact type — do not invent a new 3-tier string. This sub-project does **not** persist to `App.RiskLevel`; that's deferred to sub-project 8 (Dashboard).
- No PDF export, no historical multi-task score trend — explicitly out of scope per spec.

---

## File Structure

```
internal/
├── service/
│   ├── hardening_command.go        (modify — add ResolveEffectiveFlags, refactor BuildDPTCommand to use it)
│   ├── hardening_command_test.go   (modify — add ResolveEffectiveFlags tests)
│   ├── hardening_report.go         (new — HardeningReport type + BuildHardeningReport)
│   ├── hardening_report_test.go    (new)
│   ├── hardening_service.go        (modify — add GetReport, ErrHardeningReportNotReady, engineVersion field)
│   └── hardening_service_test.go   (modify — add GetReport tests, thread engineVersion through setup helper)
├── handler/
│   ├── hardening_handler.go        (modify — add GetReport handler)
│   └── hardening_handler_test.go   (modify — add endpoint tests, thread engineVersion through setup helper)
├── router/
│   └── router.go                   (modify — GET /hardening-tasks/:id/report route)
└── config/
    └── config.go                   (modify — add HardeningEngineVersion field + default)
.env.example                        (modify — add HARDENING_ENGINE_VERSION)
.env                                (modify — add HARDENING_ENGINE_VERSION, same value as .env.example default)
cmd/server/main.go                  (modify — pass cfg.HardeningEngineVersion into NewHardeningService)
```

Frontend (`/Users/yrighc/work/hzyz/project/BeetleShieldFrontend`):
```
src/api/types.ts        (modify — add HardeningReport* interfaces)
src/api/hardening.ts    (modify — add getHardeningReport)
src/pages/Reports.tsx   (modify — replace all mock data with real API calls)
```

---

### Task 1: `ResolveEffectiveFlags` + `BuildDPTCommand` refactor

**Files:**
- Modify: `internal/service/hardening_command.go`
- Modify: `internal/service/hardening_command_test.go`

**Interfaces:**
- Produces: `service.EffectiveFlags` struct (fields `EmulatorDetect`, `RootDetect`, `HookDetect`, `SigVerify`, `StringEncrypt`, `AssetsEncrypt`, `VMPEnabled`, all `bool`), `service.ResolveEffectiveFlags(s model.Strategy) EffectiveFlags` — consumed by Task 2 (`hardening_report.go`).

- [ ] **Step 1: Write the failing test for `ResolveEffectiveFlags`**

`internal/service/hardening_command_test.go` declares `package service` (an internal test file, not `service_test`) — reference `ResolveEffectiveFlags`/`EffectiveFlags` unqualified, no `service.` prefix. Add to `internal/service/hardening_command_test.go` (new test function, keep existing ones untouched):

```go
func TestResolveEffectiveFlags(t *testing.T) {
	cases := []struct {
		name     string
		strategy model.Strategy
		want     EffectiveFlags
	}{
		{
			name:     "all off",
			strategy: model.Strategy{},
			want:     service.EffectiveFlags{},
		},
		{
			name: "debugger alone does not enable EmulatorDetect",
			strategy: model.Strategy{
				Debugger: true,
			},
			want: service.EffectiveFlags{},
		},
		{
			name: "emulator and root detect",
			strategy: model.Strategy{
				Emulator:   true,
				RootDetect: true,
			},
			want: service.EffectiveFlags{EmulatorDetect: true, RootDetect: true},
		},
		{
			name: "hook detect from any of frida/xposed/antihook",
			strategy: model.Strategy{
				Frida: true,
			},
			want: service.EffectiveFlags{HookDetect: true},
		},
		{
			name: "signature",
			strategy: model.Strategy{
				Signature: true,
			},
			want: service.EffectiveFlags{SigVerify: true},
		},
		{
			name: "string and assets encrypt",
			strategy: model.Strategy{
				StringEncrypt: true,
				ResEncrypt:    true,
			},
			want: service.EffectiveFlags{StringEncrypt: true, AssetsEncrypt: true},
		},
		{
			name: "vmp from dex high alone",
			strategy: model.Strategy{
				DexLevel: model.DexLevelHigh,
			},
			want: service.EffectiveFlags{VMPEnabled: true},
		},
		{
			name: "vmp from so shell vmp alone",
			strategy: model.Strategy{
				SoShell: model.SoShellVMP,
			},
			want: service.EffectiveFlags{VMPEnabled: true},
		},
		{
			name: "so shell aes does not enable vmp",
			strategy: model.Strategy{
				SoShell: model.SoShellAES,
			},
			want: service.EffectiveFlags{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveEffectiveFlags(tc.strategy)
			if got != tc.want {
				t.Fatalf("ResolveEffectiveFlags(%+v) = %+v, want %+v", tc.strategy, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -run TestResolveEffectiveFlags -v`
Expected: FAIL — `undefined: ResolveEffectiveFlags`

- [ ] **Step 3: Implement `EffectiveFlags` and `ResolveEffectiveFlags`, refactor `BuildDPTCommand`**

In `internal/service/hardening_command.go`, add the new type/function and rewrite `BuildDPTCommand` to consume it:

```go
// EffectiveFlags captures which dpt.jar engine flags a Strategy actually
// turns on. This is deliberately narrower than the Strategy struct itself:
// Strategy.Debugger and SoShell values "aes"/"custom_so" are stored and
// editable in Strategy Center but were never wired to a real dpt.jar
// parameter, so they must not silently imply protection anywhere that reads
// this struct (BuildDPTCommand today, the hardening report scorer next).
type EffectiveFlags struct {
	EmulatorDetect bool
	RootDetect     bool
	HookDetect     bool
	SigVerify      bool
	StringEncrypt  bool
	AssetsEncrypt  bool
	VMPEnabled     bool
}

func ResolveEffectiveFlags(s model.Strategy) EffectiveFlags {
	return EffectiveFlags{
		EmulatorDetect: s.Emulator,
		RootDetect:     s.RootDetect,
		HookDetect:     s.AntiHook || s.Frida || s.Xposed,
		SigVerify:      s.Signature,
		StringEncrypt:  s.StringEncrypt,
		AssetsEncrypt:  s.ResEncrypt,
		VMPEnabled:     s.DexLevel == model.DexLevelHigh || s.SoShell == model.SoShellVMP,
	}
}
```

Replace the body of `BuildDPTCommand` (keep the function signature and the leading `javaBin`/`args` setup identical) — swap the nine `if input.Strategy.XXX` checks for flag reads:

```go
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

	flags := ResolveEffectiveFlags(input.Strategy)

	if flags.EmulatorDetect {
		args = append(args, "--enable-emulator-detect")
	}
	if flags.RootDetect {
		args = append(args, "--enable-root-detect")
	}
	if flags.SigVerify {
		args = append(args, "--enable-apk-sig-verify", "--apk-sig-policy", "block")
	}
	if flags.HookDetect {
		args = append(args, "--enable-hook-detect")
	}
	if flags.StringEncrypt {
		args = append(args, "--enable-string-encrypt")
	}
	if flags.AssetsEncrypt {
		args = append(args, "--enable-assets-encrypt")
	}
	if flags.VMPEnabled {
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
```

- [ ] **Step 4: Run all tests in the package to verify nothing broke**

Run: `go test ./internal/service/... -run 'TestResolveEffectiveFlags|TestBuildDPTCommand|TestNormalizeVMPRules|TestSHA256File' -v`
Expected: PASS — the pre-existing `TestBuildDPTCommand_HighStrengthMapping` and `TestBuildDPTCommand_DeduplicatesHookAndVMP` must still pass unchanged, proving the refactor preserved exact argument-list behavior.

- [ ] **Step 5: Commit**

```bash
git add internal/service/hardening_command.go internal/service/hardening_command_test.go
git commit -m "refactor: extract ResolveEffectiveFlags as single source of truth for engine flags"
```

---

### Task 2: Scoring algorithm — `hardening_report.go`

**Files:**
- Create: `internal/service/hardening_report.go`
- Create: `internal/service/hardening_report_test.go`

**Interfaces:**
- Consumes: `service.EffectiveFlags`, `service.ResolveEffectiveFlags` (Task 1); `model.HardeningTask` (existing, has `StrategySnapshot model.Strategy`, `App model.App`, `TaskNo`, `UnsignedObjectKey`/`UnsignedSHA256`, `SignedTestObjectKey`/`SignedTestSHA256`).
- Produces: `service.HardeningReport`, `service.ReportDimension`, `service.ReportChecklistItem`, `service.ReportArtifact`, `service.BuildHardeningReport(task model.HardeningTask, engineVersion string) HardeningReport` — consumed by Task 3 (`hardening_service.go`).

- [ ] **Step 1: Write the failing tests**

Create `internal/service/hardening_report_test.go`:

```go
package service_test

import (
	"testing"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/service"
)

func fullyHardenedStrategy() model.Strategy {
	return model.Strategy{
		Frida:         true,
		Xposed:        true,
		Emulator:      true,
		DexLevel:      model.DexLevelHigh,
		StringEncrypt: true,
		SoShell:       model.SoShellVMP,
		RootDetect:    true,
		Signature:     true,
		AntiHook:      true,
		ResEncrypt:    true,
	}
}

func baseReportTask(strategy model.Strategy) model.HardeningTask {
	return model.HardeningTask{
		ID:                   7,
		TaskNo:               "TASK-20260703-1",
		StrategySnapshot:     strategy,
		UnsignedObjectKey:    "com.example.app/hardening/TASK-1/unsigned.apk",
		UnsignedSHA256:       "unsignedsha",
		SignedTestObjectKey:  "com.example.app/hardening/TASK-1/signed_test.apk",
		SignedTestSHA256:     "signedsha",
		App: model.App{
			Name:        "Example App",
			PackageName: "com.example.app",
			Version:     "1.0.0",
		},
	}
}

func TestBuildHardeningReport_FullyHardenedScoresLowRisk(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(fullyHardenedStrategy()), "BeetleShield Engine v2.4.1")

	if report.BeforeScore != 100 {
		t.Fatalf("BeforeScore = %d, want 100", report.BeforeScore)
	}
	if report.AfterScore != 5 {
		t.Fatalf("AfterScore = %d, want 5 (fully hardened = weights sum to 100, clamped at floor 5)", report.AfterScore)
	}
	if report.RiskLevel != model.RiskLevelLow {
		t.Fatalf("RiskLevel = %q, want %q", report.RiskLevel, model.RiskLevelLow)
	}
}

func TestBuildHardeningReport_NoStrategyScoresMaxRiskAndCritical(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{}), "BeetleShield Engine v2.4.1")

	if report.BeforeScore != 100 {
		t.Fatalf("BeforeScore = %d, want 100", report.BeforeScore)
	}
	if report.AfterScore != 100 {
		t.Fatalf("AfterScore = %d, want 100 (nothing enabled)", report.AfterScore)
	}
	if report.RiskLevel != model.RiskLevelCritical {
		t.Fatalf("RiskLevel = %q, want %q", report.RiskLevel, model.RiskLevelCritical)
	}
}

func TestBuildHardeningReport_DebuggerFieldAloneDoesNotReduceRisk(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{Debugger: true}), "v1")
	if report.AfterScore != 100 {
		t.Fatalf("AfterScore = %d, want 100: Strategy.Debugger is not wired to any dpt.jar flag and must not affect scoring", report.AfterScore)
	}
}

func TestBuildHardeningReport_FiveDimensionsWithMergedAntiDebug(t *testing.T) {
	strategy := model.Strategy{
		Emulator: true, // anti-debug/env sub-score: 15/15
		AntiHook: true, // hook sub-score: 15/15 -> merged dimension = 30/30 = 100%
	}
	report := service.BuildHardeningReport(baseReportTask(strategy), "v1")

	if len(report.Dimensions) != 5 {
		t.Fatalf("len(Dimensions) = %d, want 5", len(report.Dimensions))
	}
	dims := map[string]service.ReportDimension{}
	for _, d := range report.Dimensions {
		dims[d.Name] = d
	}
	antiDebug, ok := dims["反调试保护"]
	if !ok {
		t.Fatalf("missing dimension 反调试保护, got %+v", report.Dimensions)
	}
	if antiDebug.Before != 0 || antiDebug.After != 100 {
		t.Fatalf("反调试保护 = %+v, want before=0 after=100", antiDebug)
	}
	dex, ok := dims["DEX 混淆"]
	if !ok || dex.After != 0 {
		t.Fatalf("DEX 混淆 = %+v (ok=%v), want after=0 (DexLevel unset)", dex, ok)
	}
}

func TestBuildHardeningReport_ChecklistHasSixItemsWithKnownStatuses(t *testing.T) {
	strategy := model.Strategy{
		Frida:      true,
		Emulator:   true,
		DexLevel:   model.DexLevelHigh,
		RootDetect: true,
	}
	report := service.BuildHardeningReport(baseReportTask(strategy), "v1")

	if len(report.Checklist) != 6 {
		t.Fatalf("len(Checklist) = %d, want 6", len(report.Checklist))
	}
	byName := map[string]service.ReportChecklistItem{}
	for _, item := range report.Checklist {
		byName[item.Name] = item
	}
	if got := byName["Frida/Xposed 注入防御"].Status; got != "已修复" {
		t.Fatalf("Frida/Xposed 注入防御 status = %q, want 已修复", got)
	}
	if got := byName["硬编码明文字符串泄露"].Status; got != "已保留" {
		t.Fatalf("硬编码明文字符串泄露 status = %q, want 已保留 (StringEncrypt not set)", got)
	}
	if got := byName["SSL Pinning 证书校验"].Status; got != "已保留" {
		t.Fatalf("SSL Pinning 证书校验 status = %q, want 已保留 (always unsupported)", got)
	}
}

func TestBuildHardeningReport_ArtifactPrefersSignedTestOverUnsigned(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{}), "BeetleShield Engine v2.4.1")

	if report.Artifact.FileName != "signed_test.apk" {
		t.Fatalf("Artifact.FileName = %q, want signed_test.apk", report.Artifact.FileName)
	}
	if report.Artifact.SHA256 != "signedsha" {
		t.Fatalf("Artifact.SHA256 = %q, want signedsha", report.Artifact.SHA256)
	}
	if report.Artifact.EngineVersion != "BeetleShield Engine v2.4.1" {
		t.Fatalf("Artifact.EngineVersion = %q", report.Artifact.EngineVersion)
	}
}

func TestBuildHardeningReport_ArtifactFallsBackToUnsignedWhenNoSignedTest(t *testing.T) {
	task := baseReportTask(model.Strategy{})
	task.SignedTestObjectKey = ""
	task.SignedTestSHA256 = ""
	report := service.BuildHardeningReport(task, "v1")

	if report.Artifact.FileName != "unsigned.apk" {
		t.Fatalf("Artifact.FileName = %q, want unsigned.apk", report.Artifact.FileName)
	}
	if report.Artifact.SHA256 != "unsignedsha" {
		t.Fatalf("Artifact.SHA256 = %q, want unsignedsha", report.Artifact.SHA256)
	}
}

func TestBuildHardeningReport_CopiesAppAndTaskIdentity(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{}), "v1")

	if report.TaskID != 7 || report.TaskNo != "TASK-20260703-1" {
		t.Fatalf("identity = %+v", report)
	}
	if report.AppName != "Example App" || report.PackageName != "com.example.app" || report.Version != "1.0.0" {
		t.Fatalf("app identity = %+v", report)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/service/... -run TestBuildHardeningReport -v`
Expected: FAIL — `undefined: service.BuildHardeningReport` (package doesn't compile)

- [ ] **Step 3: Implement `hardening_report.go`**

Create `internal/service/hardening_report.go`:

```go
package service

import (
	"path"
	"strings"

	"beetleshield-backend/internal/model"
)

// Score category weights sum to 100. These six categories drive the overall
// risk index; the frontend's 5-dimension bar chart merges the first two
// (anti-debug/env + hook/injection) into a single "反调试保护" entry — see
// docs/superpowers/specs/2026-07-03-backend-report-scoring-design.md.
const (
	weightAntiDebugEnv  = 15
	weightHookDefense   = 15
	weightSignature     = 15
	weightDexMax        = 20
	weightSoShellMax    = 20
	weightEncryptionMax = 15

	reportMinAfterScore = 5
)

type ReportDimension struct {
	Name   string `json:"name"`
	Before int    `json:"before"`
	After  int    `json:"after"`
}

type ReportChecklistItem struct {
	Name   string `json:"name"`
	Level  string `json:"level"`
	Status string `json:"status"`
	Desc   string `json:"desc"`
}

type ReportArtifact struct {
	FileName      string `json:"fileName"`
	SHA256        string `json:"sha256"`
	EngineVersion string `json:"engineVersion"`
}

type HardeningReport struct {
	TaskID      uint                   `json:"taskId"`
	TaskNo      string                 `json:"taskNo"`
	AppName     string                 `json:"appName"`
	PackageName string                 `json:"packageName"`
	Version     string                 `json:"version"`
	BeforeScore int                    `json:"beforeScore"`
	AfterScore  int                    `json:"afterScore"`
	RiskLevel   model.RiskLevel        `json:"riskLevel"`
	Dimensions  []ReportDimension      `json:"dimensions"`
	Checklist   []ReportChecklistItem  `json:"checklist"`
	Artifact    ReportArtifact         `json:"artifact"`
}

func dexScore(level model.DexObfuscationLevel) int {
	switch level {
	case model.DexLevelLow:
		return 5
	case model.DexLevelMedium:
		return 12
	case model.DexLevelHigh:
		return weightDexMax
	default:
		return 0
	}
}

func encryptionScore(flags EffectiveFlags) int {
	switch {
	case flags.StringEncrypt && flags.AssetsEncrypt:
		return weightEncryptionMax
	case flags.StringEncrypt || flags.AssetsEncrypt:
		return 8
	default:
		return 0
	}
}

func boolScore(enabled bool, weight int) int {
	if enabled {
		return weight
	}
	return 0
}

func riskLevelForScore(afterScore int) model.RiskLevel {
	switch {
	case afterScore < 25:
		return model.RiskLevelLow
	case afterScore < 50:
		return model.RiskLevelMedium
	case afterScore < 75:
		return model.RiskLevelHigh
	default:
		return model.RiskLevelCritical
	}
}

func artifactFileName(objectKey string) string {
	if objectKey == "" {
		return ""
	}
	return path.Base(objectKey)
}

func statusLabel(fixed bool) string {
	if fixed {
		return "已修复"
	}
	return "已保留"
}

// BuildHardeningReport is a pure function: given a completed task's frozen
// StrategySnapshot and artifact fields, it deterministically derives a risk
// report. It never touches the database and never mutates App.RiskLevel —
// persisting a risk level onto the App row is deferred to the Dashboard
// sub-project, which is the first consumer that actually needs to query
// apps by risk level.
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

	checklist := []ReportChecklistItem{
		{
			Name:   "Frida/Xposed 注入防御",
			Level:  "超危",
			Status: statusLabel(flags.HookDetect),
			Desc:   hookChecklistDesc(flags.HookDetect),
		},
		{
			Name:   "系统调试器绕过",
			Level:  "高危",
			Status: statusLabel(flags.EmulatorDetect),
			Desc:   envDetectChecklistDesc(flags.EmulatorDetect),
		},
		{
			Name:   "DEX 字节码明文暴露",
			Level:  "高危",
			Status: statusLabel(task.StrategySnapshot.DexLevel == model.DexLevelHigh),
			Desc:   dexChecklistDesc(task.StrategySnapshot.DexLevel),
		},
		{
			Name:   "硬编码明文字符串泄露",
			Level:  "中危",
			Status: statusLabel(flags.StringEncrypt),
			Desc:   stringEncryptChecklistDesc(flags.StringEncrypt),
		},
		{
			Name:   "设备 Root 权限滥用",
			Level:  "中危",
			Status: statusLabel(flags.RootDetect),
			Desc:   rootDetectChecklistDesc(flags.RootDetect),
		},
		{
			Name:   "SSL Pinning 证书校验",
			Level:  "低危",
			Status: statusLabel(false),
			Desc:   "检测到未配置本地证书单向校验。建议在下次加固策略中启用。",
		},
	}

	unsignedFileName := artifactFileName(task.UnsignedObjectKey)
	signedFileName := artifactFileName(task.SignedTestObjectKey)
	fileName := unsignedFileName
	sha256 := task.UnsignedSHA256
	if signedFileName != "" {
		fileName = signedFileName
		sha256 = task.SignedTestSHA256
	}

	return HardeningReport{
		TaskID:      task.ID,
		TaskNo:      task.TaskNo,
		AppName:     task.App.Name,
		PackageName: task.App.PackageName,
		Version:     task.App.Version,
		BeforeScore: 100,
		AfterScore:  afterScore,
		RiskLevel:   riskLevelForScore(afterScore),
		Dimensions:  dimensions,
		Checklist:   checklist,
		Artifact: ReportArtifact{
			FileName:      fileName,
			SHA256:        sha256,
			EngineVersion: engineVersion,
		},
	}
}

func hookChecklistDesc(enabled bool) string {
	if enabled {
		return "已植入反动态注入探针，自动识别并中断 Hook 调用。"
	}
	return "未启用 Hook 检测，建议开启反 Hook 策略。"
}

func envDetectChecklistDesc(enabled bool) string {
	if enabled {
		return "已启用模拟器与调试环境检测。"
	}
	return "未启用环境检测，建议开启。"
}

func dexChecklistDesc(level model.DexObfuscationLevel) string {
	if level == model.DexLevelHigh {
		return "已对 DEX 主体数据进行指令虚拟化（VMP）混淆。"
	}
	current := string(level)
	if current == "" {
		current = "未设置"
	}
	return "当前混淆强度为 " + strings.ToLower(current) + "，建议提升至 high。"
}

func stringEncryptChecklistDesc(enabled bool) string {
	if enabled {
		return "全局敏感明文采用 AES 加密，运行时动态解密。"
	}
	return "未启用字符串加密。"
}

func rootDetectChecklistDesc(enabled bool) string {
	if enabled {
		return "已启用多级 Root 检测。"
	}
	return "未启用 Root 检测。"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/service/... -run TestBuildHardeningReport -v`
Expected: PASS for all sub-tests.

- [ ] **Step 5: Commit**

```bash
git add internal/service/hardening_report.go internal/service/hardening_report_test.go
git commit -m "feat: add hardening report scoring algorithm"
```

---

### Task 3: `HardeningService.GetReport`

**Files:**
- Modify: `internal/service/hardening_service.go`
- Modify: `internal/service/hardening_service_test.go`

**Interfaces:**
- Consumes: `service.BuildHardeningReport` (Task 2); `HardeningRepository.FindByID` (existing, already `Preload("App")`).
- Produces: `service.ErrHardeningReportNotReady` (sentinel error); `(*HardeningService).GetReport(taskID uint) (*HardeningReport, error)` — consumed by Task 4 (handler). `NewHardeningService` gains a 7th parameter `engineVersion string` — every call site must be updated (Task 3 updates the two `internal/service` test helpers; Task 4 updates the handler test helper; Task 6 updates `cmd/server/main.go`).

- [ ] **Step 1: Write the failing tests**

Add to `internal/service/hardening_service_test.go`. First, update the two setup helpers to pass an engine version — find `setupHardeningServiceTestWithAuditAndDB` and change the `service.NewHardeningService(...)` call:

```go
	svc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		auditService,
		"BeetleShield Engine v2.4.1",
	)
```

Then add the new test functions (append to the file):

```go
func TestHardeningService_GetReportRequiresCompletedTask(t *testing.T) {
	svc, appRepo, _, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "report-queued")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, err = svc.GetReport(detail.Task.ID)
	if err != service.ErrHardeningReportNotReady {
		t.Fatalf("GetReport() on queued task err = %v, want ErrHardeningReportNotReady", err)
	}
}

func TestHardeningService_GetReportUnknownTask(t *testing.T) {
	svc, _, _, _ := setupHardeningServiceTest(t)

	_, err := svc.GetReport(999999999)
	if err != service.ErrHardeningTaskNotFound {
		t.Fatalf("GetReport() on unknown task err = %v, want ErrHardeningTaskNotFound", err)
	}
}

func TestHardeningService_GetReportOnCompletedTask(t *testing.T) {
	svc, appRepo, repo, scope := setupHardeningServiceTest(t)
	app := createHardeningServiceApp(t, appRepo, scope, "report-completed")

	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	now := time.Now()
	if err := repo.MarkTaskRunning(detail.Task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := repo.CompleteTaskForApp(detail.Task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", now); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	report, err := svc.GetReport(detail.Task.ID)
	if err != nil {
		t.Fatalf("GetReport() error = %v", err)
	}
	if report.TaskID != detail.Task.ID {
		t.Fatalf("report.TaskID = %d, want %d", report.TaskID, detail.Task.ID)
	}
	if report.AppName != app.Name || report.PackageName != app.PackageName {
		t.Fatalf("report app identity = %+v, want name=%q pkg=%q", report, app.Name, app.PackageName)
	}
	if report.Artifact.EngineVersion != "BeetleShield Engine v2.4.1" {
		t.Fatalf("report.Artifact.EngineVersion = %q", report.Artifact.EngineVersion)
	}
	if report.Artifact.FileName != "signed.apk" {
		t.Fatalf("report.Artifact.FileName = %q, want signed.apk", report.Artifact.FileName)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/service/... -run TestHardeningService_GetReport -v`
Expected: FAIL — compile error (`svc.GetReport undefined`, and `NewHardeningService` called with wrong number of args once the helper is updated but the constructor isn't yet).

- [ ] **Step 3: Implement `GetReport` and thread `engineVersion` through the constructor**

In `internal/service/hardening_service.go`:

1. Add the sentinel error next to the others:

```go
var (
	ErrHardeningAppNotFound      = errors.New("app not found")
	ErrHardeningTaskNotFound     = errors.New("hardening task not found")
	ErrHardeningActiveTaskExists = errors.New("app already has an active hardening task")
	ErrHardeningArtifactNotFound = errors.New("hardening artifact not found")
	ErrInvalidHardeningArtifact  = errors.New("invalid hardening artifact")
	ErrHardeningReportNotReady   = errors.New("hardening task not completed, report not available")
)
```

2. Add `engineVersion` to the struct and constructor:

```go
type HardeningService struct {
	hardeningRepo   *repository.HardeningRepository
	appRepo         *repository.AppRepository
	strategyService *StrategyService
	storage         DownloadURLProvider
	defaultVMPRules string
	auditService    *AuditService
	engineVersion   string
}

func NewHardeningService(
	hardeningRepo *repository.HardeningRepository,
	appRepo *repository.AppRepository,
	strategyService *StrategyService,
	storage DownloadURLProvider,
	defaultVMPRules string,
	auditService *AuditService,
	engineVersion string,
) *HardeningService {
	return &HardeningService{
		hardeningRepo:   hardeningRepo,
		appRepo:         appRepo,
		strategyService: strategyService,
		storage:         storage,
		defaultVMPRules: defaultVMPRules,
		auditService:    auditService,
		engineVersion:   engineVersion,
	}
}
```

3. Add the `GetReport` method (place after `DownloadURL`, before `generateHardeningTaskNo`):

```go
func (s *HardeningService) GetReport(taskID uint) (*HardeningReport, error) {
	task, err := s.hardeningRepo.FindByID(taskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningTaskNotFound
		}
		return nil, err
	}
	if task.Status != model.HardeningTaskStatusCompleted {
		return nil, ErrHardeningReportNotReady
	}

	report := BuildHardeningReport(*task, s.engineVersion)
	return &report, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/service/... -v`
Expected: PASS for the whole package (this also re-verifies Task 1/2's tests plus every pre-existing `hardening_service_test.go` test, since the constructor signature changed).

- [ ] **Step 5: Commit**

```bash
git add internal/service/hardening_service.go internal/service/hardening_service_test.go
git commit -m "feat: add HardeningService.GetReport"
```

---

### Task 4: HTTP endpoint — handler + router

**Files:**
- Modify: `internal/handler/hardening_handler.go`
- Modify: `internal/handler/hardening_handler_test.go`
- Modify: `internal/router/router.go`

**Interfaces:**
- Consumes: `(*service.HardeningService).GetReport` (Task 3); `service.ErrHardeningTaskNotFound`, `service.ErrHardeningReportNotReady`.
- Produces: `(*HardeningHandler).GetReport(c *gin.Context)`, route `GET /api/v1/hardening-tasks/:id/report`.

- [ ] **Step 1: Write the failing test**

First, update `setupHardeningRouter` in `internal/handler/hardening_handler_test.go` to pass the new constructor argument:

```go
	hardeningSvc := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategySvc,
		fakeHardeningHandlerURLStorage{},
		"# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		auditService,
		"BeetleShield Engine v2.4.1",
	)
```

Then append these test functions:

```go
func TestHardeningHandler_GetReportRequiresCompletedTask(t *testing.T) {
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
	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()

	reportReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/hardening-tasks/%d/report", srv.URL, created.Data.Task.ID), nil)
	reportReq.Header.Set("Authorization", "Bearer "+developerToken)
	reportResp, err := http.DefaultClient.Do(reportReq)
	if err != nil {
		t.Fatalf("report request: %v", err)
	}
	defer reportResp.Body.Close()
	if reportResp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want %d", reportResp.StatusCode, http.StatusConflict)
	}
}

func TestHardeningHandler_GetReportUnknownTask(t *testing.T) {
	srv, _, developerToken, _, _, _, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/hardening-tasks/999999999/report", nil)
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("report request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHardeningHandler_GetReportOnCompletedTaskAllowsAuditor(t *testing.T) {
	srv, _, developerToken, auditorToken, appID, hardeningRepo, _, cleanup := setupHardeningRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"appId": appID})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/hardening-tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+developerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	var created struct {
		Data service.HardeningTaskDetail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()

	now := time.Now()
	if err := hardeningRepo.MarkTaskRunning(created.Data.Task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := hardeningRepo.CompleteTaskForApp(created.Data.Task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", now); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	reportReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/hardening-tasks/%d/report", srv.URL, created.Data.Task.ID), nil)
	reportReq.Header.Set("Authorization", "Bearer "+auditorToken)
	reportResp, err := http.DefaultClient.Do(reportReq)
	if err != nil {
		t.Fatalf("report request: %v", err)
	}
	defer reportResp.Body.Close()
	if reportResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", reportResp.StatusCode, http.StatusOK)
	}

	var got struct {
		Data service.HardeningReport `json:"data"`
	}
	if err := json.NewDecoder(reportResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode report response: %v", err)
	}
	if got.Data.Artifact.FileName != "signed.apk" {
		t.Fatalf("Artifact.FileName = %q, want signed.apk", got.Data.Artifact.FileName)
	}
	if len(got.Data.Dimensions) != 5 {
		t.Fatalf("len(Dimensions) = %d, want 5", len(got.Data.Dimensions))
	}
	if len(got.Data.Checklist) != 6 {
		t.Fatalf("len(Checklist) = %d, want 6", len(got.Data.Checklist))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/handler/... -run TestHardeningHandler_GetReport -v`
Expected: FAIL — `404 Not Found` on all requests to `/report` (route doesn't exist yet), or a compile error from the updated `NewHardeningService` call if router wiring isn't done yet — either way, not passing.

- [ ] **Step 3: Implement the handler and route**

In `internal/handler/hardening_handler.go`, add after `AppHistory`:

```go
func (h *HardeningHandler) GetReport(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}

	report, err := h.svc.GetReport(id)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrHardeningTaskNotFound):
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
		case errors.Is(err, service.ErrHardeningReportNotReady):
			response.Error(c, http.StatusConflict, 40911, "加固任务未完成，无法生成报告")
		default:
			response.Error(c, http.StatusInternalServerError, 50023, "生成加固报告失败")
		}
		return
	}

	response.Success(c, http.StatusOK, report)
}
```

In `internal/router/router.go`, add the route inside the existing `hardeningTasks` group:

```go
		hardeningTasks := v1.Group("/hardening-tasks")
		hardeningTasks.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			hardeningTasks.POST("", writeRoles, deps.HardeningHandler.Create)
			hardeningTasks.GET("", deps.HardeningHandler.List)
			hardeningTasks.GET("/:id", deps.HardeningHandler.Get)
			hardeningTasks.GET("/:id/logs", deps.HardeningHandler.Logs)
			hardeningTasks.GET("/:id/report", deps.HardeningHandler.GetReport)
			hardeningTasks.GET("/:id/download-url", writeRoles, deps.HardeningHandler.DownloadURL)
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/handler/... -run TestHardeningHandler_GetReport -v`
Expected: PASS for all three new tests.

Then run the full handler package to make sure the `setupHardeningRouter` signature change didn't break other hardening handler tests:

Run: `go test ./internal/handler/... -run TestHardeningHandler -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/handler/hardening_handler.go internal/handler/hardening_handler_test.go internal/router/router.go
git commit -m "feat: expose GET /hardening-tasks/:id/report endpoint"
```

---

### Task 5: `HARDENING_ENGINE_VERSION` config + wire into `main.go`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `.env.example`
- Modify: `.env`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Produces: `config.Config.HardeningEngineVersion string` — consumed by `main.go`'s call to `service.NewHardeningService`.

- [ ] **Step 1: Add the config field**

In `internal/config/config.go`, add the field to the `Config` struct (next to the other `DPT*` fields):

```go
	DPTJarPath            string
	DPTWorkDir            string
	DPTDefaultVMPRules    string
	DPTTaskTimeoutMinutes int

	HardeningEngineVersion string
```

Add the default and the read in `Load`:

```go
	v.SetDefault("DPT_TASK_TIMEOUT_MINUTES", 60)
	v.SetDefault("HARDENING_ENGINE_VERSION", "BeetleShield Engine v2.4.1")
```

```go
		DPTTaskTimeoutMinutes: v.GetInt("DPT_TASK_TIMEOUT_MINUTES"),
		HardeningEngineVersion: v.GetString("HARDENING_ENGINE_VERSION"),
```

- [ ] **Step 2: Add to `.env.example`**

In `.env.example`, after the `DPT_TASK_TIMEOUT_MINUTES` line, add:

```
HARDENING_ENGINE_VERSION=BeetleShield Engine v2.4.1
```

- [ ] **Step 3: Add to `.env`**

Read the local `.env` file first (`cat .env`) to confirm it has the same `DPT_*` block, then add the same line in the same position:

```
HARDENING_ENGINE_VERSION=BeetleShield Engine v2.4.1
```

If `.env` is gitignored and not present in the repo, skip this step (nothing to modify) — but note it in the task's commit message or a comment to the user, since local dev needs it to avoid falling back to viper's default (which is fine here since the default already matches, but flag it explicitly rather than assuming).

- [ ] **Step 4: Wire into `main.go`**

In `cmd/server/main.go`, update the `service.NewHardeningService(...)` call to pass the new argument as the last one:

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
```

- [ ] **Step 5: Build to verify it compiles**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go .env.example cmd/server/main.go
git add .env  # only if modified in Step 3
git commit -m "feat: add HARDENING_ENGINE_VERSION config for report artifact metadata"
```

---

### Task 6: Full backend regression run

**Files:** none (verification-only task)

**Interfaces:** none

- [ ] **Step 1: Run `go vet` and `gofmt` check**

Run: `go vet ./... && gofmt -l .`
Expected: no output from either command (no vet issues, no unformatted files). If `gofmt -l .` lists files, run `gofmt -w <file>` on each and re-check.

- [ ] **Step 2: Run the full test suite**

Run: `go test ./... -v 2>&1 | tail -100`
Expected: `ok` for every package, in particular `internal/service` and `internal/handler` (this is the first time `NewHardeningService`'s new 7th parameter is exercised end-to-end across every existing caller — a mismatched arg count or wrong position would fail every hardening-related test, not just the new ones).

- [ ] **Step 3: Commit** (only if Step 1 required `gofmt -w` fixes; otherwise skip — nothing to commit)

```bash
git add -A
git commit -m "chore: gofmt fixes from report scoring work"
```

---

### Task 7: Frontend types + API client

**Files:**
- Modify: `BeetleShieldFrontend/src/api/types.ts`
- Modify: `BeetleShieldFrontend/src/api/hardening.ts`

**Interfaces:**
- Produces: TS types `HardeningReportDimension`, `HardeningReportChecklistItem`, `HardeningReportArtifact`, `HardeningReport`; function `getHardeningReport(taskId: number): Promise<HardeningReport>` — consumed by Task 8 (`Reports.tsx`).

This task has no automated test — it's a thin typed wrapper matching the existing `hardening.ts` pattern (`getHardeningTask`, `getHardeningLogs`, `getHardeningDownloadUrl` all follow this exact shape with no dedicated tests in the frontend repo). Verification is via `npm run build`'s TypeScript check plus manual verification in Task 8's browser check.

- [ ] **Step 1: Add types to `src/api/types.ts`**

Add after the existing `HardeningTask`-related types (find the `HardeningLog` interface and the `// ---- Hardening` section, append at the end of that section):

```typescript
export interface HardeningReportDimension {
  name: string
  before: number
  after: number
}

export interface HardeningReportChecklistItem {
  name: string
  level: string
  status: string
  desc: string
}

export interface HardeningReportArtifact {
  fileName: string
  sha256: string
  engineVersion: string
}

export interface HardeningReport {
  taskId: number
  taskNo: string
  appName: string
  packageName: string
  version: string
  beforeScore: number
  afterScore: number
  riskLevel: RiskLevel
  dimensions: HardeningReportDimension[]
  checklist: HardeningReportChecklistItem[]
  artifact: HardeningReportArtifact
}
```

`RiskLevel` is already defined earlier in the same file (`'low' | 'medium' | 'high' | 'critical'`, in the `// ---- Apps` section) — reuse it, do not redeclare.

- [ ] **Step 2: Add `getHardeningReport` to `src/api/hardening.ts`**

Add the import and function:

```typescript
import apiClient from './client'
import type {
  HardeningLog,
  HardeningReport,
  HardeningTask,
  HardeningTaskDetail,
  HardeningTaskStatus,
  Paginated,
} from './types'
```

(add `HardeningReport` to the existing type-only import list, keep alphabetical order as in the current file)

```typescript
export function getHardeningReport(id: number): Promise<HardeningReport> {
  return apiClient.get(`/hardening-tasks/${id}/report`) as unknown as Promise<HardeningReport>
}
```

- [ ] **Step 3: Type-check**

Run (from `BeetleShieldFrontend/`): `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
cd /Users/yrighc/work/hzyz/project/BeetleShieldFrontend
git add src/api/types.ts src/api/hardening.ts
git commit -m "feat: add hardening report API client"
```

---

### Task 8: `Reports.tsx` — replace mock data with real API

**Files:**
- Modify: `BeetleShieldFrontend/src/pages/Reports.tsx`

**Interfaces:**
- Consumes: `getHardeningReport` (Task 7), `getAppHardeningHistory` (existing, in `src/api/apps.ts`, returns `{ items: HardeningTask[] }`), `listApps` (existing, in `src/api/apps.ts`, returns `Paginated<App>`).

- [ ] **Step 1: Replace the app selector's data source**

Currently `Reports.tsx` hardcodes `mockApps` (4 fake apps) and derives `activeApp` from it. Replace with a live app list + a "most recent completed task for the selected app" lookup, since the report is keyed by `taskId`, not `appId`:

```tsx
import React, { useEffect, useState } from 'react';
import { Card, Select, Button, Table, Space, Typography, Row, Col, Progress, Empty, Spin, message } from 'antd';
import { DownloadOutlined, FilePdfOutlined, CheckCircleOutlined, InfoCircleOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { listApps, getAppHardeningHistory } from '../api/apps';
import { getHardeningReport } from '../api/hardening';
import type { App, HardeningReport } from '../api/types';
```

Replace the component body's state and data-loading logic (keep the existing `DS` style-constants object, `renderCircleScore`, and `vulnColumns` cell renderers unchanged — those are pure presentation and don't reference mock data):

```tsx
export default function Reports() {
  const [apps, setApps] = useState<App[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<number | undefined>(undefined);
  const [compareMode, setCompareMode] = useState<true | false>(true);
  const [report, setReport] = useState<HardeningReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [noCompletedTask, setNoCompletedTask] = useState(false);

  useEffect(() => {
    listApps({ page: 1, pageSize: 100 }).then((res) => {
      setApps(res.items);
      if (res.items.length > 0) {
        setSelectedAppId(res.items[0].id);
      }
    }).catch(() => {
      message.error('加载应用列表失败');
    });
  }, []);

  useEffect(() => {
    if (selectedAppId === undefined) {
      return;
    }
    setLoading(true);
    setNoCompletedTask(false);
    setReport(null);
    getAppHardeningHistory(selectedAppId)
      .then((history) => {
        const completed = history.items.find((task) => task.status === 'completed');
        if (!completed) {
          setNoCompletedTask(true);
          return null;
        }
        return getHardeningReport(completed.id);
      })
      .then((r) => {
        if (r) {
          setReport(r);
        }
      })
      .catch(() => {
        message.error('加载加固报告失败');
      })
      .finally(() => {
        setLoading(false);
      });
  }, [selectedAppId]);

  const vulnData = report
    ? report.checklist.map((item, idx) => ({ key: String(idx), ...item }))
    : [];
```

- [ ] **Step 2: Replace the app `Select` dropdown and every `activeApp.*`/`mockApps`/`chartData` reference**

Replace the `Select` block:

```tsx
            <Select
              value={selectedAppId}
              style={{ width: 220 }}
              dropdownStyle={{ backgroundColor: DS.surfaceContainer }}
              onChange={setSelectedAppId}
            >
              {apps.map(app => (
                <Option key={app.id} value={app.id}>{app.name} ({app.packageName})</Option>
              ))}
            </Select>
```

Replace every `activeApp.beforeScore` → `report?.beforeScore ?? 0`, `activeApp.afterScore` → `report?.afterScore ?? 0`, `activeApp.提升` → compute inline as a derived percentage string:

```tsx
  const improvementPercent = report && report.beforeScore > 0
    ? Math.round(((report.beforeScore - report.afterScore) / report.beforeScore) * 100)
    : 0;
```

...and use `{improvementPercent}%` wherever `{activeApp.提升}` appeared.

Replace the hardcoded `chartData` array (`反调试保护`/`DEX 混淆`/... with fixed before/after numbers) with `report?.dimensions ?? []`, and update the `.map` in the "维度对比柱状图" section to read `item.before`/`item.after` (already the field names used in the JSX, so only the data source changes — `chartData.map(...)` becomes `(report?.dimensions ?? []).map(...)`).

Replace the "加固交付凭证" card's hardcoded filename/hash/engine version:

```tsx
                <div style={{ fontFamily: DS.fontMono, fontSize: 12, color: DS.primary, wordBreak: 'break-all', marginTop: 4 }}>
                  {report?.artifact.fileName}
                </div>
```

```tsx
                <div style={{ fontFamily: DS.fontMono, fontSize: 11, color: DS.textSecondary, wordBreak: 'break-all', marginTop: 4 }}>
                  {report?.artifact.sha256}
                </div>
```

```tsx
                <div style={{ color: DS.text, fontSize: 13, marginTop: 4 }}>
                  {report?.artifact.engineVersion}
                </div>
```

- [ ] **Step 3: Handle loading and no-completed-task states**

Wrap the main content in a loading/empty guard right after the top filter row (before the "第一行：风险评分对比" `Row`):

```tsx
      {loading && (
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <Spin size="large" />
        </div>
      )}
      {!loading && noCompletedTask && (
        <Empty
          description="该应用暂无已完成的加固任务，无法生成报告"
          style={{ padding: '80px 0' }}
        />
      )}
      {!loading && !noCompletedTask && report && (
        <>
          {/* existing 第一行/第二行/第三行 Row blocks go here, unchanged except for the data-source swaps from Step 2 */}
        </>
      )}
```

Remove the "导出加固诊断报告 (PDF)" button's functionality is out of scope (per spec) — leave the button in place but it stays a no-op (no `onClick`), matching its current mock behavior (it already has no handler today).

- [ ] **Step 4: Manual browser verification**

Start the frontend dev server and the backend (`make run` in `BeetleShieldBackend`, then `npm run dev` in `BeetleShieldFrontend`). Log in, create and let a hardening task complete for at least one app (or reuse an already-completed one from earlier smoke testing), then open the Reports page:
- Confirm the app dropdown lists real apps (not "支付宝"/"微信"/mock names).
- Confirm selecting an app with a completed task shows real scores/dimensions/checklist/artifact info matching that task's strategy.
- Confirm selecting an app with no completed task shows the "该应用暂无已完成的加固任务" empty state instead of a crash or stale data.

- [ ] **Step 5: Commit**

```bash
cd /Users/yrighc/work/hzyz/project/BeetleShieldFrontend
git add src/pages/Reports.tsx
git commit -m "feat: wire Reports page to real hardening report API"
```

---

## Post-plan note

This plan intentionally does not touch `App.RiskLevel` persistence, PDF export, or historical score trends — all explicitly deferred per the spec. Sub-project 8 (Dashboard aggregation) is the next piece of the original roadmap and will be the natural place to decide whether `App.RiskLevel` gets persisted at task-completion time.
