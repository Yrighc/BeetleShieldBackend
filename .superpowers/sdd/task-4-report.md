# Task 4 Report

## Status

Completed Task 4: implemented `HardeningService` create, list, get, logs, history, and download URL behavior with TDD coverage.

## Files Changed

- `internal/service/hardening_service.go`
- `internal/service/hardening_service_test.go`
- `.superpowers/sdd/task-4-report.md`

## Commit Hash

`497244d`

## Exact Tests Run and Results

1. Red phase:

   Command:
   ```bash
   go test ./internal/service -run HardeningService -v
   ```

   Result:
   ```text
   FAIL	beetleshield-backend/internal/service [build failed]
   ```

   Key failure details:
   - `undefined: service.HardeningService`
   - `undefined: service.NewHardeningService`
   - `undefined: service.CreateHardeningTaskInput`

2. Green verification:

   Command:
   ```bash
   go test ./internal/service -run 'HardeningService|NormalizeVMPRules|BuildDPTCommand|SHA256File' -v
   ```

   Result:
   ```text
   PASS
   ok  	beetleshield-backend/internal/service	1.041s
   ```

   Passing tests:
   - `TestNormalizeVMPRules_DefaultAndCustom`
   - `TestBuildDPTCommand_HighStrengthMapping`
   - `TestBuildDPTCommand_DeduplicatesHookAndVMP`
   - `TestSHA256FileAndSignedTestArtifactPath`
   - `TestHardeningService_CreateDefaultsAndSetsAppProcessing`
   - `TestHardeningService_CreateRejectsActiveTask`
   - `TestHardeningService_CreateUsesCustomSnapshotAndRules`
   - `TestHardeningService_GetLogsAndHistory`
   - `TestHardeningService_DownloadURLArtifacts`
   - `TestHardeningService_DownloadURLErrors`
   - `TestHardeningService_ErrorMappings`

## Self-Review Notes

- Stayed within Task 4 scope and did not modify Task 1-3 files.
- Mapped missing app/task records to Task 4 service errors while preserving repository behavior.
- Added read/log/history/download error coverage so the service contract is exercised beyond creation flow.
- `Create` accepts `context.Context` for the required interface but does not currently use it internally.

## Fix Follow-Up

### Files Changed

- `internal/repository/hardening_repository.go`
- `internal/repository/hardening_repository_test.go`
- `internal/service/hardening_service.go`
- `internal/service/hardening_service_test.go`
- `.superpowers/sdd/task-4-report.md`

### Reviewer Findings Addressed

- Moved same-app active-task rejection into a repository transaction that locks the target app row with `FOR UPDATE`, checks queued/running tasks, creates the task and default steps, and updates `apps.status=processing` atomically.
- Kept `HardeningService.Create` public behavior the same by mapping repository duplicate/missing-app errors back to `ErrHardeningActiveTaskExists` and `ErrHardeningAppNotFound`.
- Reworked hardening service tests to use a unique per-run package-name scope and cleanup only rows owned by that run, instead of broad `TASK-%` or `com.hardening.service.%` cleanup.
- Added duplicate-active coverage for the atomic repository path and a concurrent same-app create regression test at the service layer.

### Exact Test Results

1. Command:
   ```bash
   go test ./internal/service -run 'HardeningService|NormalizeVMPRules|BuildDPTCommand|SHA256File' -v
   ```

   Result:
   ```text
   === RUN   TestNormalizeVMPRules_DefaultAndCustom
   --- PASS: TestNormalizeVMPRules_DefaultAndCustom (0.00s)
   === RUN   TestBuildDPTCommand_HighStrengthMapping
   --- PASS: TestBuildDPTCommand_HighStrengthMapping (0.00s)
   === RUN   TestBuildDPTCommand_DeduplicatesHookAndVMP
   --- PASS: TestBuildDPTCommand_DeduplicatesHookAndVMP (0.00s)
   === RUN   TestSHA256FileAndSignedTestArtifactPath
   --- PASS: TestSHA256FileAndSignedTestArtifactPath (0.00s)
   === RUN   TestHardeningService_CreateDefaultsAndSetsAppProcessing
   --- PASS: TestHardeningService_CreateDefaultsAndSetsAppProcessing (0.09s)
   === RUN   TestHardeningService_CreateRejectsActiveTask
   --- PASS: TestHardeningService_CreateRejectsActiveTask (0.08s)
   === RUN   TestHardeningService_CreateUsesCustomSnapshotAndRules
   --- PASS: TestHardeningService_CreateUsesCustomSnapshotAndRules (0.08s)
   === RUN   TestHardeningService_GetLogsAndHistory
   --- PASS: TestHardeningService_GetLogsAndHistory (0.08s)
   === RUN   TestHardeningService_DownloadURLArtifacts
   --- PASS: TestHardeningService_DownloadURLArtifacts (0.08s)
   === RUN   TestHardeningService_DownloadURLErrors
   --- PASS: TestHardeningService_DownloadURLErrors (0.07s)
   === RUN   TestHardeningService_ErrorMappings
   --- PASS: TestHardeningService_ErrorMappings (0.06s)
   === RUN   TestHardeningService_CreateRejectsConcurrentActiveTask
   --- PASS: TestHardeningService_CreateRejectsConcurrentActiveTask (0.08s)
   PASS
   ok  	beetleshield-backend/internal/service	1.374s
   ```

2. Command:
   ```bash
   go test ./internal/repository -run 'HardeningRepository|AppRepository' -v
   ```

   Result:
   ```text
   === RUN   TestAppRepository_CreateFindDelete
   --- PASS: TestAppRepository_CreateFindDelete (0.10s)
   === RUN   TestAppRepository_ListFilters
   --- PASS: TestAppRepository_ListFilters (0.07s)
   === RUN   TestAppRepository_UpdateStatus
   --- PASS: TestAppRepository_UpdateStatus (0.07s)
   === RUN   TestHardeningRepository_CreateTaskWithStepsAndActiveCheck
   --- PASS: TestHardeningRepository_CreateTaskWithStepsAndActiveCheck (0.08s)
   === RUN   TestHardeningRepository_CreateTaskWithStepsForAppAtomic
   --- PASS: TestHardeningRepository_CreateTaskWithStepsForAppAtomic (0.07s)
   === RUN   TestHardeningRepository_CreateTaskWithStepsForAppConcurrent
   --- PASS: TestHardeningRepository_CreateTaskWithStepsForAppConcurrent (0.09s)
   === RUN   TestHardeningRepository_QueueStepLogAndCompletion
   --- PASS: TestHardeningRepository_QueueStepLogAndCompletion (0.10s)
   === RUN   TestHardeningRepository_FailedTaskAndStepTransitions
   --- PASS: TestHardeningRepository_FailedTaskAndStepTransitions (0.09s)
   === RUN   TestHardeningRepository_TransitionStateGuards
   --- PASS: TestHardeningRepository_TransitionStateGuards (0.08s)
   === RUN   TestHardeningRepository_ListLogsAndRecoverRunning
   --- PASS: TestHardeningRepository_ListLogsAndRecoverRunning (0.09s)
   PASS
   ok  	beetleshield-backend/internal/repository	1.277s
   ```
