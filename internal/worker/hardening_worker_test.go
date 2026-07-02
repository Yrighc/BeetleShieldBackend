package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type fakeWorkerStorage struct {
	objects      map[string][]byte
	putErr       error
	putFailAfter int
	putCalls     int
	getObjectErr error
}

func (s *fakeWorkerStorage) GetObjectToFile(ctx context.Context, objectKey string, destinationPath string) error {
	if s.getObjectErr != nil {
		return s.getObjectErr
	}
	data := s.objects[objectKey]
	return os.WriteFile(destinationPath, data, 0o600)
}

func (s *fakeWorkerStorage) PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string) error {
	s.putCalls++
	if s.putErr != nil && (s.putFailAfter == 0 || s.putCalls >= s.putFailAfter) {
		return s.putErr
	}
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
	writeSigned   bool
	err           error
	lines         []string
	lastCommand   []string
	blockOnCtx    bool
}

type fakeAppStatusUpdater struct {
	err error
}

func (f fakeAppStatusUpdater) UpdateStatus(id uint, status model.AppStatus) error {
	return f.err
}

func (r *fakeEngineRunner) Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error {
	r.lastCommand = append([]string{}, req.Command...)
	for _, line := range r.lines {
		onLine(model.HardeningLogLevelInfo, line)
	}
	if r.blockOnCtx {
		<-ctx.Done()
		return ctx.Err()
	}
	output := commandValue(req.Command, "-o")
	if r.writeUnsigned {
		if err := os.WriteFile(output, []byte("unsigned"), 0o600); err != nil {
			return err
		}
	}
	if r.writeSigned {
		signedPath := strings.TrimSuffix(output, filepath.Ext(output)) + "_signed" + filepath.Ext(output)
		if err := os.WriteFile(signedPath, []byte("signed"), 0o600); err != nil {
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

func setupWorkerTest(t *testing.T) (*gorm.DB, *HardeningWorker, *repository.HardeningRepository, *repository.AppRepository, *fakeWorkerStorage, *fakeEngineRunner) {
	t.Helper()
	lockFile := acquireHardeningTestLock(t)
	t.Cleanup(func() { releaseHardeningTestLock(t, lockFile) })
	cfg := &config.Config{
		DBHost:     "localhost",
		DBPort:     "5432",
		DBUser:     "root",
		DBPassword: "root",
		DBName:     "beetleshield",
		DBSSLMode:  "disable",
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
	runner := &fakeEngineRunner{
		writeUnsigned: true,
		writeSigned:   true,
		lines:         []string{"engine started", "All done."},
	}
	w := NewHardeningWorker(repo, appRepo, storage, runner, HardeningWorkerConfig{
		JarPath:         "/opt/dpt.jar",
		WorkDir:         t.TempDir(),
		DefaultVMPRules: "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		Timeout:         time.Minute,
	})
	return database, w, repo, appRepo, storage, runner
}

func acquireHardeningTestLock(t *testing.T) *os.File {
	t.Helper()
	lockFile, err := os.OpenFile("/tmp/beetleshield-hardening-tests.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open hardening test lock: %v", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		lockFile.Close()
		t.Fatalf("acquire hardening test lock: %v", err)
	}
	return lockFile
}

func releaseHardeningTestLock(t *testing.T, lockFile *os.File) {
	t.Helper()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("release hardening test lock: %v", err)
	}
	if err := lockFile.Close(); err != nil {
		t.Fatalf("close hardening test lock: %v", err)
	}
}

func createWorkerTask(t *testing.T, database *gorm.DB, repo *repository.HardeningRepository, appRepo *repository.AppRepository, storage *fakeWorkerStorage, suffix string) model.HardeningTask {
	t.Helper()
	app := model.App{
		Name:        "Worker App " + suffix,
		PackageName: "com.hardening.worker." + suffix,
		Version:     "1.0.0",
		Tag:         model.AppTagTool,
		Status:      model.AppStatusProcessing,
		ObjectKey:   "worker/" + suffix + "/input.apk",
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		UploadedBy:  1,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("create app: %v", err)
	}
	storage.objects[app.ObjectKey] = []byte("input apk")

	task := model.HardeningTask{
		TaskNo:                   "TASK-WORKER-" + strings.ToUpper(suffix),
		AppID:                    app.ID,
		Status:                   model.HardeningTaskStatusQueued,
		StrategyName:             "默认加固模板",
		StrategySnapshot:         model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, RootDetect: true, Signature: true},
		VMPRulesText:             "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		EnableFileIntegrityCheck: true,
		EnableProxyDetect:        true,
		CreatedBy:                1,
	}
	if err := repo.CreateTaskWithSteps(&task); err != nil {
		t.Fatalf("CreateTaskWithSteps() error = %v", err)
	}
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", task.ID).Update("created_at", time.Unix(1, 0)).Error; err != nil {
		t.Fatalf("set created_at: %v", err)
	}
	return task
}

func TestHardeningWorker_ProcessNextSuccessUploadsArtifacts(t *testing.T) {
	database, w, repo, appRepo, storage, runner := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, "success")

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

	app, err := appRepo.FindByID(found.AppID)
	if err != nil {
		t.Fatalf("FindByID(app) error = %v", err)
	}
	if app.Status != model.AppStatusCompleted {
		t.Fatalf("app status = %s", app.Status)
	}

	steps, err := repo.Steps(task.ID)
	if err != nil {
		t.Fatalf("Steps() error = %v", err)
	}
	for _, step := range steps {
		if step.Status != model.HardeningStepStatusSuccess {
			t.Fatalf("step %s status = %s", step.StepKey, step.Status)
		}
	}
}

func TestHardeningWorker_ProcessNextNoUnsignedFails(t *testing.T) {
	database, w, repo, appRepo, storage, runner := setupWorkerTest(t)
	runner.writeUnsigned = false
	runner.writeSigned = true
	task := createWorkerTask(t, database, repo, appRepo, storage, "fail")

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
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed", found.Status)
	}

	app, err := appRepo.FindByID(found.AppID)
	if err != nil {
		t.Fatalf("FindByID(app) error = %v", err)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}
}

func TestHardeningWorker_ProcessNextWithoutSignedArtifactStillCompletes(t *testing.T) {
	database, w, repo, appRepo, storage, runner := setupWorkerTest(t)
	runner.writeSigned = false
	task := createWorkerTask(t, database, repo, appRepo, storage, "unsigned-only")

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
		t.Fatalf("task status = %s, want completed", found.Status)
	}
	if found.SignedTestObjectKey != "" {
		t.Fatalf("SignedTestObjectKey = %q, want empty", found.SignedTestObjectKey)
	}

	logs, err := repo.Logs(task.ID, repository.HardeningLogFilter{Limit: 50})
	if err != nil {
		t.Fatalf("Logs() error = %v", err)
	}
	foundWarn := false
	for _, log := range logs {
		if log.Level == model.HardeningLogLevelWarn && strings.Contains(log.Message, "未发现测试签名产物") {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Fatal("expected warn log for missing signed artifact")
	}

	app, err := appRepo.FindByID(found.AppID)
	if err != nil {
		t.Fatalf("FindByID(app) error = %v", err)
	}
	if app.Status != model.AppStatusCompleted {
		t.Fatalf("app status = %s, want completed", app.Status)
	}
}

func TestHardeningWorker_ProcessNextUploadFailureMarksTaskAndAppFailed(t *testing.T) {
	database, w, repo, appRepo, storage, runner := setupWorkerTest(t)
	storage.putErr = errors.New("upload failed")
	storage.putFailAfter = 2
	task := createWorkerTask(t, database, repo, appRepo, storage, "upload-fail")

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
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed", found.Status)
	}
	if !strings.Contains(found.ErrorSummary, "upload failed") {
		t.Fatalf("error summary = %q, want upload failure", found.ErrorSummary)
	}
	if found.UnsignedObjectKey != "" || found.SignedTestObjectKey != "" {
		t.Fatalf("artifact keys should not be persisted on failure: %+v", found)
	}
	if _, ok := storage.objects[artifactObjectKey(found, "unsigned", ".apk")]; !ok {
		t.Fatal("expected unsigned artifact upload before failure")
	}
	if _, ok := storage.objects[artifactObjectKey(found, "signed_test", ".apk")]; ok {
		t.Fatal("signed artifact should not upload after failure")
	}

	app, err := appRepo.FindByID(found.AppID)
	if err != nil {
		t.Fatalf("FindByID(app) error = %v", err)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}

	uploadStep, err := repo.FindStep(task.ID, model.HardeningStepUploadArtifacts)
	if err != nil {
		t.Fatalf("FindStep(upload) error = %v", err)
	}
	if uploadStep.Status != model.HardeningStepStatusFailed {
		t.Fatalf("upload step status = %s, want failed", uploadStep.Status)
	}

	_ = runner
}

func TestHardeningWorker_ProcessNextContextCancellationMarksTaskAndAppFailed(t *testing.T) {
	database, w, repo, appRepo, storage, runner := setupWorkerTest(t)
	runner.blockOnCtx = true
	w.cfg.Timeout = 20 * time.Millisecond
	task := createWorkerTask(t, database, repo, appRepo, storage, "ctx-timeout")

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
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed", found.Status)
	}
	if !strings.Contains(found.ErrorSummary, context.DeadlineExceeded.Error()) {
		t.Fatalf("error summary = %q, want context deadline exceeded", found.ErrorSummary)
	}

	app, err := appRepo.FindByID(found.AppID)
	if err != nil {
		t.Fatalf("FindByID(app) error = %v", err)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}
}

func TestHardeningWorker_RecoverRunningMarksTasksAndAppsFailed(t *testing.T) {
	database, w, repo, appRepo, storage, _ := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, "recover")
	if err := repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}

	if err := w.RecoverRunning(context.Background()); err != nil {
		t.Fatalf("RecoverRunning() error = %v", err)
	}

	found, err := repo.FindByID(task.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s", found.Status)
	}

	app, err := appRepo.FindByID(found.AppID)
	if err != nil {
		t.Fatalf("FindByID(app) error = %v", err)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s", app.Status)
	}
}

func TestHardeningWorker_RecoverRunningReturnsErrorWhenAppStatusUpdateFails(t *testing.T) {
	database, w, repo, appRepo, storage, _ := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, "recover-missing-app")
	if err := repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	w.appStatusUpdater = fakeAppStatusUpdater{err: gorm.ErrRecordNotFound}

	err := w.RecoverRunning(context.Background())
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("RecoverRunning() error = %v, want %v", err, gorm.ErrRecordNotFound)
	}
}

func TestHardeningWorker_RunStepOutOfOrderFails(t *testing.T) {
	database, w, repo, appRepo, storage, _ := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, "out-of-order")
	now := time.Now()
	if err := repo.MarkTaskRunning(task.ID, now); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}

	err := w.runStep(task.ID, model.HardeningStepRunEngine, func(step *model.HardeningStep) error {
		return nil
	})
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("runStep() error = %v, want %v", err, gorm.ErrRecordNotFound)
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
