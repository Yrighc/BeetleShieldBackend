# Task 2 报告：Persist `App.RiskLevel` when a hardening task completes

## 状态：DONE

全部 8 个步骤（含 TDD 步骤 1-6、Step 7 完整测试集、Step 8 提交）已按 brief
逐条完成，DB-backed 测试全部通过，改动已提交到 `feat/dashboard-overview` 分支。

## 时间线与环境说明

任务开始时发现一个持续运行的 `go run ./cmd/server` 进程（PID 33143）连接同一
Postgres 实例，其 `hardening_worker` 后台轮询可能与本任务新增/修改的 DB
集成测试产生竞争。按当时的指令未自行终止该进程，先完成了 Step 1-6（TDD
改代码 + 编译期自检），并将 Step 7/8 上报为阻塞项。

协调者随后确认已停止该进程（PID 33143 及其子进程 PID 33498），并指示继续
Step 7、Step 8。本次继续前先独立复核：

```
$ ps aux | grep -E 'cmd/server|exe/server' | grep -v grep
(无输出，确认无残留进程)
```

确认干净后，执行了 Step 7 的两条测试命令与 Step 8 的提交。

## 已完成的改动（TDD 步骤 1-6）

### Step 1-2：更新并确认测试先失败
`internal/repository/hardening_repository_test.go` 的
`TestHardeningRepository_CompleteTaskForAppUpdatesTaskAndAppAtomically`：
`CompleteTaskForApp` 调用追加 `model.RiskLevelHigh` 参数，并新增
`foundApp.RiskLevel` 断言（与 brief 给出的代码逐字一致）。

执行：
```
go test ./internal/repository/... -run TestHardeningRepository_CompleteTaskForAppUpdatesTaskAndAppAtomically -v
```
输出（编译失败，证实测试改动先行且确实会失败）：
```
internal/repository/hardening_repository_test.go:417:119: too many arguments in call to repo.CompleteTaskForApp
	have (uint, string, number, string, string, number, string, "time".Time, model.RiskLevel)
	want (uint, string, int64, string, string, int64, string, "time".Time)
FAIL	beetleshield-backend/internal/repository [build failed]
FAIL
```
与 brief Step 2 预期的"编译错误、参数不匹配"性质一致（编译器报的是
"too many arguments"而非字面的"not enough arguments"，但根因相同：签名尚未更新）。

### Step 3：`internal/repository/hardening_repository.go`
- `CompleteTaskForApp` 新增尾部参数 `riskLevel model.RiskLevel`，App 侧
  `Updates` 从单一 `status` 改为
  `map[string]interface{}{"status": model.AppStatusCompleted, "risk_level": riskLevel}`。
- `FailTaskForApp` 的 App 更新改为 `map[string]interface{}{"status": model.AppStatusFailed}`。
- `transitionTaskForApp` / `transitionTaskForAppTx` 最后一个参数由
  `appStatus model.AppStatus` 改为 `appUpdates map[string]interface{}`，内部对 App 表的更新
  由 `Update("status", appStatus)` 改为 `Updates(appUpdates)`。
- `RecoverRunningTasks` 中对 `transitionTaskForAppTx` 的调用同步改为传入
  `map[string]interface{}{"status": model.AppStatusFailed}`。

与 brief 中给出的代码逐字一致（已逐行 diff 核对）。

### Step 4：修复全部调用方
- `internal/repository/hardening_repository_test.go`：确认只有 Step 1 中那一处调用（已核实，无遗漏）。
- `internal/service/hardening_service_test.go`：两处调用追加 `, model.RiskLevelLow`。
- `internal/service/audit_retrofit_test.go`：一处调用追加 `, model.RiskLevelLow`。
- `internal/handler/hardening_handler_test.go`：三处调用追加 `, model.RiskLevelLow`。
- `internal/worker/hardening_worker.go`：在调用 `CompleteTaskForApp` 前新增
  `riskLevel := service.ResolveRiskLevel(task.StrategySnapshot)`，并将其作为最后一个参数传入。
  该文件已导入 `beetleshield-backend/internal/service`，无需新增 import。

### Step 5：编译自检
```
$ go build ./... && echo "BUILD OK"
BUILD OK
$ go vet ./... && echo "VET OK"
VET OK
$ gofmt -l .
（无输出，说明全部文件已是 gofmt 标准格式）
```

### Step 6：新增 worker 端到端测试
在 `internal/worker/hardening_worker_test.go` 末尾追加
`TestHardeningWorker_ProcessNextPersistsAppRiskLevel`（与 brief 给出的代码逐字一致），
验证 `ProcessNext` 处理完成后 `App.RiskLevel` 被持久化为 `medium`。

已手工核对该测试注释里的算术推导，对照
`internal/service/hardening_report.go` 中的
`computeScoreBreakdown`/`riskLevelForScore`/权重常量：
`createWorkerTask` 的 `StrategySnapshot` 为
`{DexLevel: high, SoShell: vmp, RootDetect: true, Signature: true}`：
antiDebugEnvScore=15（RootDetect）、hookScore=0（无 HookDetect）、
sigScore=15（Signature）、dexPoints=20（high=weightDexMax）、
soPoints=20（VMP=weightSoShellMax）、encryptPoints=0，
sum=70，afterScore=100-70=30，落在 `[25,50)` 区间对应 `medium`。
与测试注释、断言完全吻合。

## Step 7：完整受影响测试集（已执行，全部 PASS）

命令一（brief 指定的过滤测试集）：
```
go test ./internal/repository/... ./internal/service/... ./internal/handler/... ./internal/worker/... \
  -run 'CompleteTaskForApp|FailTaskForApp|ProcessNextPersistsAppRiskLevel|ProcessNextSuccessUploadsArtifacts|RecoverRunning' -v
```
关键输出：
```
--- PASS: TestHardeningRepository_CompleteTaskForAppUpdatesTaskAndAppAtomically (0.17s)
--- PASS: TestHardeningRepository_FailTaskForAppRollsBackWhenAppUpdateFails (0.10s)
--- PASS: TestHardeningRepository_ListLogsAndRecoverRunning (0.12s)
--- PASS: TestHardeningRepository_RecoverRunningTasksRollsBackWhenAppUpdateFails (0.10s)
PASS
ok  	beetleshield-backend/internal/repository	0.972s
testing: warning: no tests to run   # service 包：本次 -run 正则未命中任何测试名（该包里
                                     # CompleteTaskForApp 相关调用嵌在其他名字的测试函数里）
PASS
ok  	beetleshield-backend/internal/service	0.945s [no tests to run]
testing: warning: no tests to run   # handler 包同理
PASS
ok  	beetleshield-backend/internal/handler	1.331s [no tests to run]
--- PASS: TestHardeningWorker_ProcessNextSuccessUploadsArtifacts (0.19s)
--- PASS: TestHardeningWorker_RecoverRunningMarksTasksAndAppsFailed (0.12s)
--- PASS: TestHardeningWorker_RecoverRunningCleansUpOrphanedArtifacts (0.10s)
--- PASS: TestHardeningWorker_RecoverRunningHonorsCanceledContext (0.11s)
--- PASS: TestHardeningWorker_RecoverRunningReturnsErrorWithoutDriftWhenAppUpdateFails (0.11s)
--- PASS: TestHardeningWorker_StartReportsRecoverRunningError (0.14s)
--- PASS: TestHardeningWorker_ProcessNextPersistsAppRiskLevel (0.14s)
PASS
ok  	beetleshield-backend/internal/worker	2.697s
```
`service`/`handler` 包的 "no tests to run" 是预期行为——这两个包里包含
`CompleteTaskForApp` 调用的测试函数名不匹配该 `-run` 正则（例如
`TestHardeningService_...`、`TestHardeningHandler_...`），会在命令二的全量运行中被覆盖。

命令二（全量运行，捕获 `-run` 过滤器可能漏掉的用例）：
```
go test ./internal/repository/... ./internal/service/... ./internal/handler/... ./internal/worker/... -v
```
结果汇总（四个包全部 `ok`，日志中 `PASS` 160 处、`--- FAIL` 0 处）：
```
ok  	beetleshield-backend/internal/repository	4.657s
ok  	beetleshield-backend/internal/service	6.268s
ok  	beetleshield-backend/internal/handler	6.853s
ok  	beetleshield-backend/internal/worker	4.911s
```
`internal/service`、`internal/handler` 里 `CompleteTaskForApp` 相关的调用点
（`hardening_service_test.go`、`audit_retrofit_test.go`、`hardening_handler_test.go`
共 6 处新增 `model.RiskLevelLow` 参数）均在这次全量运行中被间接执行且全部通过，
没有因签名变更或 `risk_level` 落库而引入回归。

## Step 8：提交（已完成）

```bash
git add internal/repository/hardening_repository.go internal/repository/hardening_repository_test.go \
  internal/service/hardening_service_test.go internal/service/audit_retrofit_test.go \
  internal/handler/hardening_handler_test.go \
  internal/worker/hardening_worker.go internal/worker/hardening_worker_test.go
git commit -m "feat: persist App.RiskLevel when a hardening task completes"
```
提交结果：
```
[feat/dashboard-overview 48b28a8] feat: persist App.RiskLevel when a hardening task completes
 7 files changed, 55 insertions(+), 16 deletions(-)
```

## 涉及文件

- `internal/repository/hardening_repository.go`（生产代码，签名变更）
- `internal/repository/hardening_repository_test.go`（更新既有测试）
- `internal/service/hardening_service_test.go`（更新调用方）
- `internal/service/audit_retrofit_test.go`（更新调用方）
- `internal/handler/hardening_handler_test.go`（更新调用方）
- `internal/worker/hardening_worker.go`（生产代码，计算并传入 riskLevel）
- `internal/worker/hardening_worker_test.go`（新增端到端测试）

`git diff --stat`（提交前）：
```
 internal/handler/hardening_handler_test.go       |  6 ++---
 internal/repository/hardening_repository.go      | 23 ++++++++++++-------
 internal/repository/hardening_repository_test.go |  5 ++++-
 internal/service/audit_retrofit_test.go          |  2 +-
 internal/service/hardening_service_test.go       |  4 ++--
 internal/worker/hardening_worker.go              |  3 ++-
 internal/worker/hardening_worker_test.go         | 28 ++++++++++++++++++++++++
 7 files changed, 55 insertions(+), 16 deletions(-)
```
七个文件均与 brief 列出的清单一致，无遗漏、无额外文件改动。commit hash: `48b28a8`。

## 自检小结

- 代码 diff 逐一对照 brief 给出的原文，确认字符级一致（包括注释、缩进）。
- 所有生产代码路径（`CompleteTaskForApp`/`FailTaskForApp`/`transitionTaskForApp`/
  `transitionTaskForAppTx`/`RecoverRunningTasks`/worker 侧调用）均已改为新签名，
  没有遗留旧签名调用（`go build`/`go vet` 全绿 + Step 7 全量测试通过可佐证）。
- 手工核对了新增 worker 测试里 risk score 的算术推导，与
  `internal/service/hardening_report.go` 中的常量/函数定义完全吻合，不是照抄 brief
  未加验证。
- Step 7 两条命令均已实际运行并核对输出：过滤命令四包全绿（含 service/handler
  的 "no tests to run"，已确认是预期行为而非误配置）；全量命令四包 `ok`，
  日志里 `PASS` 160 次、`--- FAIL` 0 次。
- 提交前二次核实无残留 `cmd/server`/`exe/server` 进程，避免测试期间的并发写入
  干扰结果。
- 提交只包含 brief 列出的 7 个源码文件，未夹带 `.superpowers/sdd/task-2-report.md`
  等文档改动，符合"只改需要改的文件"的规范。
- 注意：`internal/service/hardening_report.go` 第 167-170 行的注释
  （"persisting a risk level onto the App row is deferred to the Dashboard
  sub-project..."）在本任务完成后已经过时（本任务正是该 Dashboard 子项目
  落地这一持久化的第一步），但 brief 未要求修改该注释、也不在本任务的文件
  清单内，按"严格按需修改"的规范未做改动，留给后续任务/人工决定是否更新。

## 遗留风险 / 后续建议

1. `internal/service/hardening_report.go` 中提到"持久化 risk level 推迟到
   Dashboard 子项目"的注释已过时，建议后续任务（或后续 sub-project 的收尾
   commit）顺手更新，避免误导后来者。不在本任务范围内，未做改动。
2. 无其他遗留问题；Step 7/8 均已完成，任务收尾。
