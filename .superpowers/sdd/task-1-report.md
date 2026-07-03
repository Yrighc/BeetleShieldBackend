# Task 1 报告：提取 `computeScoreBreakdown` + 新增 `ResolveRiskLevel`

> 注：本文件此前内容是更早一轮"Task 1"（`ResolveEffectiveFlags` 抽取，已提交为 commit `0ae4413`）的报告。
> 当前任务是 Dashboard overview 计划里新的 Task 1（提取 `computeScoreBreakdown`、新增 `ResolveRiskLevel`），
> 与 `ResolveEffectiveFlags` 是两轮不同的重构，本文件内容已替换为本轮任务的报告。

## 变更文件

- `internal/service/hardening_report.go`
  - 新增私有类型 `scoreBreakdown` 及函数 `computeScoreBreakdown(flags EffectiveFlags, dexLevel model.DexObfuscationLevel) scoreBreakdown`：
    把原来内联在 `BuildHardeningReport` 里的六项打分逻辑（`antiDebugEnvScore`/`hookScore`/`sigScore`/`dexPoints`/`soPoints`/`encryptPoints`/`afterScore`）抽成单一函数。
  - 新增导出函数 `ResolveRiskLevel(strategy model.Strategy) model.RiskLevel`：
    内部调用 `ResolveEffectiveFlags` + `computeScoreBreakdown` + `riskLevelForScore`，供后续 Task（worker 在任务完成时持久化 `App.RiskLevel`）复用，避免与 `BuildHardeningReport` 的评分逻辑重复实现、产生漂移。
  - `BuildHardeningReport` 内部改为调用 `computeScoreBreakdown`，用返回的 `scoreBreakdown`（局部变量 `b`）替换原来的六个局部变量引用，行为完全不变。
- `internal/service/hardening_report_test.go`
  - 追加三个测试：`TestResolveRiskLevel_NoStrategyIsCritical`、`TestResolveRiskLevel_FullyHardenedIsLow`、`TestResolveRiskLevel_MatchesBuildHardeningReportRiskLevel`（后者用多组策略断言 `ResolveRiskLevel` 与 `BuildHardeningReport(...).RiskLevel` 计算结果一致）。
  - 均按 brief（`.superpowers/sdd/task-1-brief.md`）中给出的代码原样添加，复用文件内已有的 `fullyHardenedStrategy()` / `baseReportTask()` helper。

未修改任何公共接口签名（`BuildHardeningReport` 签名不变），未涉及数据库 migration/config 改动。

## 测试命令与结果

### Step 2：确认新测试先失败（RED）

```
go test ./internal/service/... -run TestResolveRiskLevel -v
```

输出（节选）：
```
internal/service/hardening_report_test.go:171:20: undefined: service.ResolveRiskLevel
internal/service/hardening_report_test.go:177:20: undefined: service.ResolveRiskLevel
internal/service/hardening_report_test.go:192:18: undefined: service.ResolveRiskLevel
FAIL	beetleshield-backend/internal/service [build failed]
```
结论：FAIL，原因与预期一致（`ResolveRiskLevel` 尚未实现，编译期报 `undefined`）。

### Step 4：实现后重新运行（GREEN）

```
go test ./internal/service/... -run 'TestResolveRiskLevel|TestBuildHardeningReport' -v
```

输出：
```
=== RUN   TestBuildHardeningReport_FullyHardenedScoresLowRisk
--- PASS: TestBuildHardeningReport_FullyHardenedScoresLowRisk (0.00s)
=== RUN   TestBuildHardeningReport_NoStrategyScoresMaxRiskAndCritical
--- PASS: TestBuildHardeningReport_NoStrategyScoresMaxRiskAndCritical (0.00s)
=== RUN   TestBuildHardeningReport_DebuggerFieldAloneDoesNotReduceRisk
--- PASS: TestBuildHardeningReport_DebuggerFieldAloneDoesNotReduceRisk (0.00s)
=== RUN   TestBuildHardeningReport_FiveDimensionsWithMergedAntiDebug
--- PASS: TestBuildHardeningReport_FiveDimensionsWithMergedAntiDebug (0.00s)
=== RUN   TestBuildHardeningReport_ChecklistHasSixItemsWithKnownStatuses
--- PASS: TestBuildHardeningReport_ChecklistHasSixItemsWithKnownStatuses (0.00s)
=== RUN   TestBuildHardeningReport_ArtifactPrefersSignedTestOverUnsigned
--- PASS: TestBuildHardeningReport_ArtifactPrefersSignedTestOverUnsigned (0.00s)
=== RUN   TestBuildHardeningReport_ArtifactFallsBackToUnsignedWhenNoSignedTest
--- PASS: TestBuildHardeningReport_ArtifactFallsBackToUnsignedWhenNoSignedTest (0.00s)
=== RUN   TestBuildHardeningReport_CopiesAppAndTaskIdentity
--- PASS: TestBuildHardeningReport_CopiesAppAndTaskIdentity (0.00s)
=== RUN   TestResolveRiskLevel_NoStrategyIsCritical
--- PASS: TestResolveRiskLevel_NoStrategyIsCritical (0.00s)
=== RUN   TestResolveRiskLevel_FullyHardenedIsLow
--- PASS: TestResolveRiskLevel_FullyHardenedIsLow (0.00s)
=== RUN   TestResolveRiskLevel_MatchesBuildHardeningReportRiskLevel
--- PASS: TestResolveRiskLevel_MatchesBuildHardeningReportRiskLevel (0.00s)
PASS
ok  	beetleshield-backend/internal/service	0.564s
```
结论：11/11 PASS，包括全部预置的 `TestBuildHardeningReport_*` 回归测试（证明重构未改变可观察行为）与 3 个新增的 `TestResolveRiskLevel_*` 测试。

### 额外自检

```
go vet ./...
```
输出：无（clean）。

```
gofmt -l .
```
输出：无（clean，无需要格式化的文件）。

```
go test ./internal/service/... -v
```
完整 `service` 包测试（含需要真实 Postgres 的 repository 相关用例）全部 PASS，未因本次改动引入新的失败（日志中出现的 `record not found` / `audit repository is not configured` 均为既有测试用例的预期行为，与本次改动无关）。

## 自检说明

1. **改动范围**：仅涉及 `internal/service/hardening_report.go` 与 `internal/service/hardening_report_test.go` 两个文件，未触碰路由/handler/repository/worker 层，也未修改 `BuildHardeningReport` 对外签名，符合"按需最小改动"要求。
2. **行为等价性**：`computeScoreBreakdown` 是对原内联代码的纯粹搬移（无任何计算逻辑变化），`BuildHardeningReport` 的返回值构造只是把六个局部变量替换成 `scoreBreakdown` 结构体的字段访问；已有全部 `TestBuildHardeningReport_*` 用例作为回归保护，全部原样通过。
3. **`ResolveRiskLevel` 的正确性**：新增测试 `TestResolveRiskLevel_MatchesBuildHardeningReportRiskLevel` 用多组代表性策略（空策略/全量加固/仅模拟器+root/仅 Frida+DEX 高混淆/仅 Debugger 字段）交叉验证 `ResolveRiskLevel` 与 `BuildHardeningReport(...).RiskLevel` 结果一致，覆盖了"Debugger 字段不影响评分"这类边界情况。
4. **数据库 / 配置改动**：无。本任务是纯计算逻辑提取，不涉及 `Migrate()`、`config.go`、`.env` 改动。
5. **审计日志 / 状态机影响**：无。`ResolveRiskLevel` 是纯函数（无副作用、不访问数据库），本任务不修改 `hardening_worker` 状态机或审计记录路径；后续 Task（worker 侧持久化 `App.RiskLevel`）会是首个调用方，届时需要评估是否需要为该次持久化补充审计记录，但那是下一个任务的范畴。
6. **风险点**：无已知风险。`scoreBreakdown` 与 `computeScoreBreakdown` 均为包内私有，不影响外部调用方；唯一新增的导出符号 `ResolveRiskLevel` 签名与 brief 中约定的一致（`func ResolveRiskLevel(strategy model.Strategy) model.RiskLevel`）。

## Commit

```
refactor: extract computeScoreBreakdown, add ResolveRiskLevel

（提交哈希见下方 git log，文件：internal/service/hardening_report.go、internal/service/hardening_report_test.go）
```
