# Task 2 Report: Hardening Repository Queue, Step, Log, and History Persistence

## Status

Implemented Task 2 repository persistence changes and added repository-level integration tests.
The repository package compiles successfully. Full integration test execution remains blocked in this environment because the required local PostgreSQL instance on `localhost:5432` is not running, and no local Docker or PostgreSQL runtime is available to start it here.

## Files Changed

- `internal/repository/app_repository.go`
- `internal/repository/app_repository_test.go`
- `internal/repository/hardening_repository.go`
- `internal/repository/hardening_repository_test.go`

## Commit Hash

`757c72d` (`feat: add hardening repository queue`)

## Exact Tests Run and Results

1. Red phase:

```bash
go test ./internal/repository -run HardeningRepository -v
```

Result: `FAIL`

Reason:
- `undefined: HardeningRepository`
- `undefined: NewHardeningRepository`
- `undefined: HardeningLogFilter`
- `undefined: HardeningListFilter`

2. Extended red phase after adding `AppRepository.UpdateStatus` coverage:

```bash
go test ./internal/repository -run 'HardeningRepository|AppRepository' -v
```

Result: `FAIL`

Reason:
- same missing hardening repository symbols as above
- `repo.UpdateStatus undefined (type *AppRepository has no field or method UpdateStatus)`

3. Post-implementation targeted verification:

```bash
go test ./internal/repository -run 'HardeningRepository|AppRepository' -v
```

Result: `FAIL`

Reason:
- runtime environment failure, not compile failure
- PostgreSQL connection refused on `localhost:5432` for all repository integration tests

Representative error:

```text
failed to connect to `user=root database=beetleshield`:
[::1]:5432 (localhost): dial error: dial tcp [::1]:5432: connect: connection refused
127.0.0.1:5432 (localhost): dial error: dial tcp 127.0.0.1:5432: connect: connection refused
```

4. Compile-only verification:

```bash
go test ./internal/repository -run '^$'
```

Result: `PASS`

Output:

```text
ok  	beetleshield-backend/internal/repository	0.300s [no tests to run]
```

## Self-Review Notes

- Added a dedicated `HardeningRepository` with transactional task+step creation, queue lookup, task lifecycle updates, recovery, list/history queries, step persistence, and log persistence.
- Kept the implementation aligned with existing repository patterns and reused GORM/query style already present in the codebase.
- Added a focused `AppRepository.UpdateStatus` helper plus direct test coverage for it.
- Used unique task and package prefixes in the new integration tests to avoid colliding with existing data and to accommodate the branch's current Task 1 changes.
- Remaining verification gap is environmental only: the repository integration suite needs the expected local Postgres service to be reachable.

## Fix Section

### Files Changed

- `internal/repository/hardening_repository.go`
- `internal/repository/hardening_repository_test.go`

### Review Fixes Applied

- Hardened task and step transition helpers so they only advance from the expected current state and return `gorm.ErrRecordNotFound` when the ID is missing or the row is not in the required state.
- Added integration coverage for:
  - `MarkTaskFailed`
  - `FinishStepFailed`
  - task/step transition guard behavior
  - `Logs` filtering by `StepKey` and `AfterID`
  - `List` filtering by `Status` and `AppID`
  - `RecoverRunningTasks` marking a running step failed
  - round-trip persistence of `StrategyName`, `StrategySnapshot`, and `VMPRulesText`

### Exact Test Results

1. Required integration command:

```bash
go test ./internal/repository -run 'HardeningRepository|AppRepository' -v
```

Result: `FAIL`

Reason:
- environment-level PostgreSQL connection failure on `localhost:5432`

Representative output:

```text
failed to connect to `user=root database=beetleshield`:
127.0.0.1:5432 (localhost): dial error: dial tcp 127.0.0.1:5432: connect: connection refused
[::1]:5432 (localhost): dial error: dial tcp [::1]:5432: connect: connection refused
```

2. Compile-only verification:

```bash
go test ./internal/repository -run '^$'
```

Result: `PASS`

Output:

```text
ok  	beetleshield-backend/internal/repository	0.505s [no tests to run]
```
