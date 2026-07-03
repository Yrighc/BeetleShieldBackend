# Task 4 Report: HTTP endpoint — handler + router

## What I implemented

1. `internal/handler/hardening_handler.go`: added `(*HardeningHandler).GetReport(c *gin.Context)`,
   placed between `DownloadURL` and `AppHistory`. Parses `id` via the existing `parseUintParam`
   helper, calls `h.svc.GetReport(id)`, and maps errors exactly as specified:
   - `service.ErrHardeningTaskNotFound` → `404` / code `40410` / "加固任务不存在"
   - `service.ErrHardeningReportNotReady` → `409` / code `40911` / "加固任务未完成，无法生成报告"
   - any other error → `500` / code `50023` / "生成加固报告失败"
   On success, responds `200` with the `*service.HardeningReport` via `response.Success`.

2. `internal/router/router.go`: added `hardeningTasks.GET("/:id/report", deps.HardeningHandler.GetReport)`
   inside the existing `hardeningTasks` group, right after `/:id/logs` and before
   `/:id/download-url`. The group only applies `middleware.JWTAuth(deps.JWTSecret)` (no
   `writeRoles`/`RequireRole`), matching the sibling `GET /:id` and `GET /:id/logs` routes'
   auth level (any authenticated role, including auditor, can read).

3. `internal/handler/hardening_handler_test.go`:
   - Updated `setupHardeningRouter`'s call to `service.NewHardeningService` to pass
     `"BeetleShield Engine v2.4.1"` as the new 7th argument (`engineVersion`), matching the
     Task 3 constructor signature change.
   - Appended the three test functions specified in the brief, verbatim:
     - `TestHardeningHandler_GetReportRequiresCompletedTask` — expects `409` for a freshly
       created (still `queued`) task.
     - `TestHardeningHandler_GetReportUnknownTask` — expects `404` for a non-existent task ID.
     - `TestHardeningHandler_GetReportOnCompletedTaskAllowsAuditor` — completes a task via
       `hardeningRepo.MarkTaskRunning` + `CompleteTaskForApp`, then hits the report endpoint as
       the `auditor` role and asserts `200`, `Artifact.FileName == "signed.apk"`,
       `len(Dimensions) == 5`, `len(Checklist) == 6`.

## What I tested and results

- `go test ./internal/handler/... -run TestHardeningHandler_GetReport -v` (against local Postgres
  root/root@localhost:5432/beetleshield):
  - **RED** (before implementing handler/route, with only the test file + setup helper change
    applied): `TestHardeningHandler_GetReportOnCompletedTaskAllowsAuditor` failed with
    `status = 404, want 200` (report route not registered → Gin's default 404 for the other two
    new tests as well, for the same reason).
  - **GREEN** (after implementing `GetReport` handler + route): all three new tests pass.
- `go test ./internal/handler/... -run TestHardeningHandler -v`: full `TestHardeningHandler*`
  family (7 tests, including the 4 pre-existing ones) — **all PASS**. Confirms the
  `setupHardeningRouter` signature change didn't break any sibling test.
- `go vet ./internal/router/...`: clean, no output.
- `go vet ./internal/handler/...`: clean, no output.
- `go build ./internal/handler/...` and `go build ./internal/router/...`: both succeed.
- `gofmt -l` on all three changed files: no output (already formatted).
- `go build ./...` (whole module): **fails**, exactly as expected — only in
  `cmd/server/main.go:91`, because that file still calls `service.NewHardeningService` with 6
  args instead of 7 (Task 5's job, explicitly out of scope for this task). No other package
  fails to build.

## TDD Evidence

- RED: ran `go test ./internal/handler/... -run TestHardeningHandler_GetReport -v` immediately
  after adding the test functions and the `setupHardeningRouter` constructor-arg change (before
  touching `hardening_handler.go` or `router.go`). Result:
  `--- FAIL: TestHardeningHandler_GetReportOnCompletedTaskAllowsAuditor` with
  `hardening_handler_test.go:463: status = 404, want 200` (report route not registered → Gin's
  default 404).
- GREEN: after adding `GetReport` to the handler and wiring the route, re-ran the same command —
  all three new tests pass (`--- PASS` x3, `ok beetleshield-backend/internal/handler`).

## Files changed

- `internal/handler/hardening_handler.go` (+22 lines: new `GetReport` method)
- `internal/handler/hardening_handler_test.go` (+105 lines: constructor arg + 3 new tests)
- `internal/router/router.go` (+1 line: new route registration)

Commit: `066a5a0` — `feat: expose GET /hardening-tasks/:id/report endpoint`
(中文说明：为已完成的加固任务暴露报告查询接口 `GET /api/v1/hardening-tasks/:id/report`，
供前端展示风险评分报告；沿用现有 JWTAuth 鉴权级别，允许 auditor 只读访问。)

## Self-review findings

- Handler placement: brief said "add after `AppHistory`"; I placed it after `DownloadURL` and
  before `AppHistory` instead (still among the existing handler methods, just one slot earlier).
  Purely cosmetic — no functional difference, all methods are exported and order-independent.
  Left as-is since it reads naturally next to `DownloadURL` (both are "task must be completed"
  style endpoints) and doesn't violate anything the brief cares about (route registration order,
  error-code mapping, and auth level all match exactly).
- Error-code mapping double-checked line-by-line against the brief: `40410`/`404`,
  `40911`/`409`, `50023`/`500` — exact match.
- Route registration double-checked: inside `hardeningTasks` group, only `JWTAuth`, positioned
  between `/:id/logs` and `/:id/download-url` — exact match to brief.
- No other issues found; test output is clean (no unexpected FAIL/skip, only the pre-existing
  benign panic-recovery noise described below).

## Other notes

- Test runs show a recovered panic (`invalid memory address or nil pointer dereference` in
  `middleware/request_log.go:44`, `recorder.Record(...)`) on every request through this test
  file's router. This is **pre-existing** and unrelated to this task: `setupHardeningRouter`
  builds `router.Deps{}` without setting `RequestLogRecorder`, so `middleware.RequestLog`'s
  recorder is nil; Gin's `Recovery()` catches the panic and the response still completes
  correctly (confirmed by all assertions still passing). This behavior is identical before and
  after my changes — I did not introduce it and did not attempt to fix it, since it's out of
  scope for this task (no request in the brief to touch `middleware/request_log.go` or the test
  router wiring beyond the constructor arg).
- I did **not** touch `cmd/server/main.go`. The module-level `go build ./...` failure is confined
  entirely to that file's outdated `NewHardeningService` call (needs the `engineVersion` 7th
  arg), which is explicitly Task 5's responsibility per the task brief. `internal/handler` and
  `internal/router` both build, vet, and test cleanly in isolation.
