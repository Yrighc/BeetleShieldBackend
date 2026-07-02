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
		Name:        "Repo App " + suffix,
		PackageName: "com.hardening.repo." + suffix,
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

func newRepoTask(taskNo string, appID uint, status model.HardeningTaskStatus) model.HardeningTask {
	return model.HardeningTask{
		TaskNo:           taskNo,
		AppID:            appID,
		Status:           status,
		StrategyName:     "默认加固模板",
		StrategySnapshot: model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP},
		VMPRulesText:     "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		CreatedBy:        1,
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
