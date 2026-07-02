package repository

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
)

type hardeningRepoTestScope struct {
	runID string
}

func newHardeningRepoTestScope() hardeningRepoTestScope {
	return hardeningRepoTestScope{
		runID: fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff),
	}
}

func (s hardeningRepoTestScope) packageNamePrefix() string {
	return "com.hardening.repo." + s.runID
}

func (s hardeningRepoTestScope) packageName(suffix string) string {
	return s.packageNamePrefix() + "." + suffix
}

func (s hardeningRepoTestScope) taskNo(suffix string) string {
	return "TASK-REPO-" + s.runID + "-" + suffix
}

func setupHardeningRepo(t *testing.T) (*HardeningRepository, *AppRepository, *gorm.DB, hardeningRepoTestScope) {
	t.Helper()
	scope := newHardeningRepoTestScope()
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
	cleanupHardeningRepoData(t, database, scope)
	t.Cleanup(func() { cleanupHardeningRepoData(t, database, scope) })
	return NewHardeningRepository(database), NewAppRepository(database), database, scope
}

func cleanupHardeningRepoData(t *testing.T, database *gorm.DB, scope hardeningRepoTestScope) {
	t.Helper()

	database.Exec(`
		DELETE FROM hardening_logs
		WHERE task_id IN (
			SELECT id FROM hardening_tasks WHERE task_no LIKE ?
		)
	`, scope.taskNo("%"))
	database.Exec(`
		DELETE FROM hardening_steps
		WHERE task_id IN (
			SELECT id FROM hardening_tasks WHERE task_no LIKE ?
		)
	`, scope.taskNo("%"))
	database.Unscoped().Where("task_no LIKE ?", scope.taskNo("%")).Delete(&model.HardeningTask{})
	database.Unscoped().Where("package_name LIKE ?", scope.packageNamePrefix()+".%").Delete(&model.App{})
}

func createRepoApp(t *testing.T, appRepo *AppRepository, scope hardeningRepoTestScope, suffix string) model.App {
	t.Helper()
	app := model.App{
		Name:        "Repo App " + suffix,
		PackageName: scope.packageName(suffix),
		Version:     "1.0.0",
		Tag:         model.AppTagTool,
		Status:      model.AppStatusUnprotected,
		ObjectKey:   "repo/" + suffix + "/app.apk",
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:      fmt.Sprintf("%064d", len(suffix)+1),
		UploadedBy:  1,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("Create app: %v", err)
	}
	return app
}

func newRepoTask(scope hardeningRepoTestScope, suffix string, appID uint, status model.HardeningTaskStatus) model.HardeningTask {
	return model.HardeningTask{
		TaskNo:           scope.taskNo(suffix),
		AppID:            appID,
		Status:           status,
		StrategyName:     "默认加固模板",
		StrategySnapshot: model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP},
		VMPRulesText:     "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		CreatedBy:        1,
	}
}

func TestHardeningRepository_CreateTaskWithStepsAndActiveCheck(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, scope, "active")
	task := newRepoTask(scope, "active", app.ID, model.HardeningTaskStatusQueued)

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

func TestHardeningRepository_CreateTaskWithStepsForAppAtomic(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, scope, "atomic")
	task := newRepoTask(scope, "atomic", app.ID, model.HardeningTaskStatusQueued)

	if err := repo.CreateTaskWithStepsForApp(&task, model.AppStatusProcessing); err != nil {
		t.Fatalf("CreateTaskWithStepsForApp() error = %v", err)
	}

	foundApp, err := appRepo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() app error = %v", err)
	}
	if foundApp.Status != model.AppStatusProcessing {
		t.Fatalf("app status = %s, want processing", foundApp.Status)
	}

	steps, err := repo.Steps(task.ID)
	if err != nil {
		t.Fatalf("Steps() error = %v", err)
	}
	if len(steps) != len(defaultHardeningSteps) {
		t.Fatalf("len(steps) = %d, want %d", len(steps), len(defaultHardeningSteps))
	}

	second := newRepoTask(scope, "atomic-dup", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithStepsForApp(&second, model.AppStatusProcessing); !errors.Is(err, ErrActiveHardeningTaskExists) {
		t.Fatalf("duplicate CreateTaskWithStepsForApp() err = %v, want %v", err, ErrActiveHardeningTaskExists)
	}
}

func TestHardeningRepository_CreateTaskWithStepsForAppConcurrent(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, scope, "atomic-concurrent")

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			task := newRepoTask(scope, fmt.Sprintf("atomic-concurrent-%d", idx), app.ID, model.HardeningTaskStatusQueued)
			<-start
			errs <- repo.CreateTaskWithStepsForApp(&task, model.AppStatusProcessing)
		}(i)
	}

	close(start)
	wg.Wait()
	close(errs)

	var successCount int
	var activeErrCount int
	for err := range errs {
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, ErrActiveHardeningTaskExists):
			activeErrCount++
		default:
			t.Fatalf("CreateTaskWithStepsForApp() concurrent err = %v", err)
		}
	}
	if successCount != 1 || activeErrCount != 1 {
		t.Fatalf("success=%d activeErr=%d, want 1/1", successCount, activeErrCount)
	}

	history, err := repo.RecentByApp(app.ID, 10)
	if err != nil {
		t.Fatalf("RecentByApp() error = %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("len(history) = %d, want 1", len(history))
	}
}

func TestHardeningRepository_QueueStepLogAndCompletion(t *testing.T) {
	repo, appRepo, database, scope := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, scope, "queue")
	first := newRepoTask(scope, "queue-1", app.ID, model.HardeningTaskStatusQueued)
	second := newRepoTask(scope, "queue-2", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&second); err != nil {
		t.Fatalf("Create second: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := repo.CreateTaskWithSteps(&first); err != nil {
		t.Fatalf("Create first: %v", err)
	}
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", second.ID).Update("created_at", time.Unix(1, 0)).Error; err != nil {
		t.Fatalf("backdate second created_at: %v", err)
	}
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", first.ID).Update("created_at", time.Unix(2, 0)).Error; err != nil {
		t.Fatalf("backdate first created_at: %v", err)
	}

	next, err := repo.NextQueuedTask()
	if err != nil {
		t.Fatalf("NextQueuedTask() error = %v", err)
	}
	if next.TaskNo != second.TaskNo {
		t.Fatalf("next task = %s, want %s", next.TaskNo, second.TaskNo)
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
	if found.StrategyName != "默认加固模板" {
		t.Fatalf("StrategyName = %q, want %q", found.StrategyName, "默认加固模板")
	}
	if found.StrategySnapshot.DexLevel != model.DexLevelHigh || found.StrategySnapshot.SoShell != model.SoShellVMP {
		t.Fatalf("unexpected StrategySnapshot: %+v", found.StrategySnapshot)
	}
	if found.VMPRulesText != "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**" {
		t.Fatalf("VMPRulesText = %q", found.VMPRulesText)
	}
}

func TestHardeningRepository_FailedTaskAndStepTransitions(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, scope, "failed")
	task := newRepoTask(scope, "failed", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}

	now := time.Now()
	if err := repo.MarkTaskRunning(task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	step, err := repo.FindStep(task.ID, model.HardeningStepRunEngine)
	if err != nil {
		t.Fatalf("FindStep() error = %v", err)
	}
	if err := repo.StartStep(step.ID, now.Add(time.Second)); err != nil {
		t.Fatalf("StartStep() error = %v", err)
	}
	if err := repo.FinishStepFailed(step.ID, "engine crashed", now.Add(2*time.Second)); err != nil {
		t.Fatalf("FinishStepFailed() error = %v", err)
	}
	if err := repo.MarkTaskFailed(task.ID, "engine crashed", now.Add(3*time.Second)); err != nil {
		t.Fatalf("MarkTaskFailed() error = %v", err)
	}

	failedStep, err := repo.FindStep(task.ID, model.HardeningStepRunEngine)
	if err != nil {
		t.Fatalf("FindStep() after failure error = %v", err)
	}
	if failedStep.Status != model.HardeningStepStatusFailed || failedStep.ErrorMessage != "engine crashed" {
		t.Fatalf("unexpected failed step: %+v", failedStep)
	}

	failedTask, err := repo.FindByID(task.ID)
	if err != nil {
		t.Fatalf("FindByID() after failure error = %v", err)
	}
	if failedTask.Status != model.HardeningTaskStatusFailed || failedTask.ErrorSummary != "engine crashed" {
		t.Fatalf("unexpected failed task: %+v", failedTask)
	}
}

func TestHardeningRepository_TransitionStateGuards(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, scope, "guards")
	task := newRepoTask(scope, "guards", app.ID, model.HardeningTaskStatusQueued)
	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}

	now := time.Now()
	if err := repo.MarkTaskCompleted(task.ID, "unsigned.apk", 12, "abc", "signed.apk", 13, "def", now); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("MarkTaskCompleted() error = %v, want %v", err, gorm.ErrRecordNotFound)
	}
	if err := repo.MarkTaskRunning(task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := repo.MarkTaskRunning(task.ID, now.Add(time.Second)); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("MarkTaskRunning() second call error = %v, want %v", err, gorm.ErrRecordNotFound)
	}
	if err := repo.MarkTaskFailed(task.ID+9999, "missing", now.Add(2*time.Second)); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("MarkTaskFailed() missing task error = %v, want %v", err, gorm.ErrRecordNotFound)
	}

	step, err := repo.FindStep(task.ID, model.HardeningStepPrepareInput)
	if err != nil {
		t.Fatalf("FindStep() error = %v", err)
	}
	if err := repo.FinishStepSuccess(step.ID, now); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("FinishStepSuccess() without StartStep error = %v, want %v", err, gorm.ErrRecordNotFound)
	}
	if err := repo.StartStep(step.ID, now); err != nil {
		t.Fatalf("StartStep() error = %v", err)
	}
	if err := repo.StartStep(step.ID, now.Add(time.Second)); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("StartStep() second call error = %v, want %v", err, gorm.ErrRecordNotFound)
	}
	if err := repo.FinishStepFailed(step.ID, "boom", now.Add(2*time.Second)); err != nil {
		t.Fatalf("FinishStepFailed() error = %v", err)
	}
	if err := repo.FinishStepSuccess(step.ID, now.Add(3*time.Second)); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("FinishStepSuccess() after failure error = %v, want %v", err, gorm.ErrRecordNotFound)
	}
}

func TestHardeningRepository_ListLogsAndRecoverRunning(t *testing.T) {
	repo, appRepo, _, scope := setupHardeningRepo(t)
	app := createRepoApp(t, appRepo, scope, "history")
	otherApp := createRepoApp(t, appRepo, scope, "history-other")
	completed := newRepoTask(scope, "history-completed", app.ID, model.HardeningTaskStatusCompleted)
	running := newRepoTask(scope, "history-running", app.ID, model.HardeningTaskStatusRunning)
	other := newRepoTask(scope, "history-other", otherApp.ID, model.HardeningTaskStatusFailed)
	if err := repo.CreateTaskWithSteps(&completed); err != nil {
		t.Fatalf("Create completed: %v", err)
	}
	if err := repo.CreateTaskWithSteps(&running); err != nil {
		t.Fatalf("Create running: %v", err)
	}
	if err := repo.CreateTaskWithSteps(&other); err != nil {
		t.Fatalf("Create other: %v", err)
	}

	items, total, err := repo.List(HardeningListFilter{Search: "Repo App history", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("total=%d len=%d, want 3", total, len(items))
	}

	statusItems, statusTotal, err := repo.List(HardeningListFilter{
		Status:   string(model.HardeningTaskStatusRunning),
		AppID:    app.ID,
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("List() with status+app filter error = %v", err)
	}
	if statusTotal != 1 || len(statusItems) != 1 || statusItems[0].ID != running.ID {
		t.Fatalf("unexpected status/app filtered tasks: total=%d items=%+v", statusTotal, statusItems)
	}
	history, err := repo.RecentByApp(app.ID, 5)
	if err != nil {
		t.Fatalf("RecentByApp() error = %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("len(history) = %d, want 2", len(history))
	}

	now := time.Now()
	runningStep, err := repo.FindStep(running.ID, model.HardeningStepPrepareInput)
	if err != nil {
		t.Fatalf("FindStep() running task error = %v", err)
	}
	if err := repo.StartStep(runningStep.ID, now); err != nil {
		t.Fatalf("StartStep() running task error = %v", err)
	}

	completedStep, err := repo.FindStep(completed.ID, model.HardeningStepPrepareInput)
	if err != nil {
		t.Fatalf("FindStep() completed task error = %v", err)
	}
	if err := repo.AppendLog(&model.HardeningLog{TaskID: completed.ID, StepID: &completedStep.ID, Level: model.HardeningLogLevelInfo, Message: "first prepare"}); err != nil {
		t.Fatalf("AppendLog() first error = %v", err)
	}
	if err := repo.AppendLog(&model.HardeningLog{TaskID: completed.ID, StepID: &completedStep.ID, Level: model.HardeningLogLevelInfo, Message: "second prepare"}); err != nil {
		t.Fatalf("AppendLog() second error = %v", err)
	}
	otherStep, err := repo.FindStep(completed.ID, model.HardeningStepParsePackage)
	if err != nil {
		t.Fatalf("FindStep() other step error = %v", err)
	}
	if err := repo.AppendLog(&model.HardeningLog{TaskID: completed.ID, StepID: &otherStep.ID, Level: model.HardeningLogLevelInfo, Message: "parse package"}); err != nil {
		t.Fatalf("AppendLog() third error = %v", err)
	}

	allLogs, err := repo.Logs(completed.ID, HardeningLogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Logs() all error = %v", err)
	}
	if len(allLogs) != 3 {
		t.Fatalf("len(allLogs) = %d, want 3", len(allLogs))
	}
	filteredLogs, err := repo.Logs(completed.ID, HardeningLogFilter{
		StepKey: model.HardeningStepPrepareInput,
		AfterID: allLogs[0].ID,
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("Logs() filtered error = %v", err)
	}
	if len(filteredLogs) != 1 || filteredLogs[0].Message != "second prepare" {
		t.Fatalf("unexpected filtered logs: %+v", filteredLogs)
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
	recoveredStep, err := repo.FindStep(running.ID, model.HardeningStepPrepareInput)
	if err != nil {
		t.Fatalf("FindStep() recovered step error = %v", err)
	}
	if recoveredStep.Status != model.HardeningStepStatusFailed || recoveredStep.ErrorMessage != "服务重启导致任务中断" {
		t.Fatalf("unexpected recovered step: %+v", recoveredStep)
	}
}

func TestCleanupHardeningRepoData_OnlyRemovesScopedRows(t *testing.T) {
	_, appRepo, database, scope := setupHardeningRepo(t)
	otherScope := newHardeningRepoTestScope()
	t.Cleanup(func() { cleanupHardeningRepoData(t, database, otherScope) })

	scopedApp := createRepoApp(t, appRepo, scope, "cleanup")
	otherApp := createRepoApp(t, appRepo, otherScope, "cleanup")

	scopedTask := newRepoTask(scope, "cleanup", scopedApp.ID, model.HardeningTaskStatusQueued)
	otherTask := newRepoTask(otherScope, "cleanup", otherApp.ID, model.HardeningTaskStatusQueued)

	repo := NewHardeningRepository(database)
	if err := repo.CreateTaskWithSteps(&scopedTask); err != nil {
		t.Fatalf("CreateTaskWithSteps() scoped error = %v", err)
	}
	if err := repo.CreateTaskWithSteps(&otherTask); err != nil {
		t.Fatalf("CreateTaskWithSteps() other error = %v", err)
	}

	cleanupHardeningRepoData(t, database, scope)

	var scopedTaskCount int64
	if err := database.Model(&model.HardeningTask{}).Where("task_no = ?", scopedTask.TaskNo).Count(&scopedTaskCount).Error; err != nil {
		t.Fatalf("count scoped task: %v", err)
	}
	if scopedTaskCount != 0 {
		t.Fatalf("scoped task count = %d, want 0", scopedTaskCount)
	}

	var otherTaskCount int64
	if err := database.Model(&model.HardeningTask{}).Where("task_no = ?", otherTask.TaskNo).Count(&otherTaskCount).Error; err != nil {
		t.Fatalf("count other task: %v", err)
	}
	if otherTaskCount != 1 {
		t.Fatalf("other task count = %d, want 1", otherTaskCount)
	}

	var scopedAppCount int64
	if err := database.Model(&model.App{}).Where("package_name = ?", scopedApp.PackageName).Count(&scopedAppCount).Error; err != nil {
		t.Fatalf("count scoped app: %v", err)
	}
	if scopedAppCount != 0 {
		t.Fatalf("scoped app count = %d, want 0", scopedAppCount)
	}

	var otherAppCount int64
	if err := database.Model(&model.App{}).Where("package_name = ?", otherApp.PackageName).Count(&otherAppCount).Error; err != nil {
		t.Fatalf("count other app: %v", err)
	}
	if otherAppCount != 1 {
		t.Fatalf("other app count = %d, want 1", otherAppCount)
	}
}
