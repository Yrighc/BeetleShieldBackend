package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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
	objects                     map[string][]byte
	putErr                      error
	putFailAfter                int
	putCalls                    int
	deleteErr                   error
	deleteCalls                 []string
	onPutFail                   func()
	failDeleteOnCanceledContext bool
	getObjectErr                error
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
		if s.onPutFail != nil {
			s.onPutFail()
		}
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

func (s *fakeWorkerStorage) DeleteObject(ctx context.Context, objectKey string) error {
	s.deleteCalls = append(s.deleteCalls, objectKey)
	if s.failDeleteOnCanceledContext {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.objects, objectKey)
	return nil
}

type fakeEngineRunner struct {
	writeUnsigned bool
	writeSigned   bool
	err           error
	lines         []string
	lastCommand   []string
	blockOnCtx    bool
	beforeReturn  func() error
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
	if r.beforeReturn != nil {
		if err := r.beforeReturn(); err != nil {
			return err
		}
	}
	return r.err
}

type workerTestScope struct {
	taskPrefix    string
	packagePrefix string
}

func commandValue(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func setupWorkerTest(t *testing.T) (*gorm.DB, *HardeningWorker, *repository.HardeningRepository, *repository.AppRepository, *fakeWorkerStorage, *fakeEngineRunner, workerTestScope) {
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

	scope := newWorkerTestScope(t)
	t.Cleanup(func() {
		database.Exec("DELETE FROM hardening_logs WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE ?)", scope.taskPrefix+"%")
		database.Exec("DELETE FROM hardening_steps WHERE task_id IN (SELECT id FROM hardening_tasks WHERE task_no LIKE ?)", scope.taskPrefix+"%")
		database.Exec("DELETE FROM hardening_tasks WHERE task_no LIKE ?", scope.taskPrefix+"%")
		database.Unscoped().Where("package_name LIKE ?", scope.packagePrefix+"%").Delete(&model.App{})
	})

	appRepo := repository.NewAppRepository(database)
	repo := repository.NewHardeningRepository(database)
	storage := &fakeWorkerStorage{objects: map[string][]byte{}}
	runner := &fakeEngineRunner{
		writeUnsigned: true,
		writeSigned:   true,
		lines:         []string{"engine started", "All done."},
	}
	w := NewHardeningWorker(repo, storage, runner, HardeningWorkerConfig{
		JarPath:         "/opt/dpt.jar",
		WorkDir:         t.TempDir(),
		DefaultVMPRules: "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		Timeout:         time.Minute,
	})
	return database, w, repo, appRepo, storage, runner, scope
}

func registerWorkerAppUpdateFailure(t *testing.T, database *gorm.DB, name string, err error) {
	t.Helper()
	if regErr := database.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "apps" {
			tx.AddError(err)
		}
	}); regErr != nil {
		t.Fatalf("register update callback: %v", regErr)
	}
	t.Cleanup(func() {
		if removeErr := database.Callback().Update().Remove(name); removeErr != nil {
			t.Fatalf("remove update callback: %v", removeErr)
		}
	})
}

func registerWorkerAppUpdateFailureOnce(t *testing.T, database *gorm.DB, name string, err error) {
	t.Helper()
	failed := false
	if regErr := database.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "apps" && !failed {
			failed = true
			tx.AddError(err)
		}
	}); regErr != nil {
		t.Fatalf("register update callback: %v", regErr)
	}
	t.Cleanup(func() {
		if removeErr := database.Callback().Update().Remove(name); removeErr != nil {
			t.Fatalf("remove update callback: %v", removeErr)
		}
	})
}

func newWorkerTestScope(t *testing.T) workerTestScope {
	t.Helper()
	namespace := fmt.Sprintf("%07x-%x", checksumString(t.Name()), time.Now().UnixNano())
	return workerTestScope{
		taskPrefix:    "TASK-W-" + strings.ToUpper(namespace),
		packagePrefix: "com.hardening.worker." + namespace,
	}
}

func checksumString(value string) uint32 {
	var sum uint32
	for i := 0; i < len(value); i++ {
		sum = sum*33 + uint32(value[i])
	}
	return sum
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

func createWorkerTask(t *testing.T, database *gorm.DB, repo *repository.HardeningRepository, appRepo *repository.AppRepository, storage *fakeWorkerStorage, scope workerTestScope, suffix string) model.HardeningTask {
	t.Helper()
	objectKeyBase := strings.ToLower(strings.ReplaceAll(scope.taskPrefix, "TASK-W-", ""))
	app := model.App{
		Name:        "Worker App " + suffix,
		PackageName: scope.packagePrefix + "." + suffix,
		Version:     "1.0.0",
		Tag:         model.AppTagTool,
		Status:      model.AppStatusProcessing,
		ObjectKey:   "worker/" + objectKeyBase + "/" + suffix + "/input.apk",
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		UploadedBy:  1,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("create app: %v", err)
	}
	storage.objects[app.ObjectKey] = []byte("input apk")

	task := model.HardeningTask{
		TaskNo:                   fmt.Sprintf("%s-%06x", scope.taskPrefix, checksumString(suffix)&0xffffff),
		AppID:                    app.ID,
		Status:                   model.HardeningTaskStatusQueued,
		StrategyName:             "默认加固模板",
		StrategySnapshot:         model.Strategy{DexLevel: model.DexLevelHigh, SoShell: model.SoShellVMP, RootDetect: true, Signature: true},
		VMPRulesText:             "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**",
		EnableFileIntegrityCheck: true,
		EnableProxyDetect:        true,
		CreatedBy:                1,
	}
	if err := repo.CreateTaskWithStepsForApp(&task, model.AppStatusProcessing); err != nil {
		t.Fatalf("CreateTaskWithStepsForApp() error = %v", err)
	}
	if err := database.Model(&model.HardeningTask{}).Where("id = ?", task.ID).Update("created_at", time.Unix(1, 0)).Error; err != nil {
		t.Fatalf("set created_at: %v", err)
	}
	return task
}

func TestHardeningWorker_ProcessNextSuccessUploadsArtifacts(t *testing.T) {
	database, w, repo, appRepo, storage, runner, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "success")

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
	database, w, repo, appRepo, storage, runner, scope := setupWorkerTest(t)
	runner.writeUnsigned = false
	runner.writeSigned = true
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "fail")

	processed, err := w.ProcessNext(context.Background())
	if !processed {
		t.Fatal("processed = false, want true")
	}
	if err == nil || !strings.Contains(err.Error(), "未生成未签名加固产物") {
		t.Fatalf("ProcessNext() error = %v, want missing unsigned artifact", err)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed", found.Status)
	}

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}
}

func TestHardeningWorker_ProcessNextReturnsMarkFailedErrorAfterRunFailure(t *testing.T) {
	database, w, repo, appRepo, storage, runner, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "mark-failed-error")
	runErr := errors.New("engine crashed")
	runner.err = runErr
	runner.beforeReturn = func() error {
		return database.Model(&model.HardeningTask{}).
			Where("id = ?", task.ID).
			Update("status", model.HardeningTaskStatusCompleted).Error
	}

	processed, err := w.ProcessNext(context.Background())
	if !processed {
		t.Fatal("processed = false, want true")
	}
	if !errors.Is(err, runErr) {
		t.Fatalf("ProcessNext() error = %v, want %v", err, runErr)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("ProcessNext() error = %v, want %v", err, gorm.ErrRecordNotFound)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	if found.Status != model.HardeningTaskStatusCompleted {
		t.Fatalf("task status = %s, want completed after failed persistence", found.Status)
	}

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if app.Status != model.AppStatusProcessing {
		t.Fatalf("app status = %s, want processing after rollback", app.Status)
	}
}

func TestHardeningWorker_ProcessNextRecoversWhenCompletionTransitionFails(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "completion-rollback")
	updateErr := errors.New("apps status update failed")
	registerWorkerAppUpdateFailureOnce(t, database, "worker-complete-app-update", updateErr)

	processed, err := w.ProcessNext(context.Background())
	if !processed {
		t.Fatal("processed = false, want true")
	}
	if !errors.Is(err, updateErr) {
		t.Fatalf("ProcessNext() error = %v, want %v", err, updateErr)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed (task must not get stuck in running when completion persistence fails)", found.Status)
	}
	if !strings.Contains(found.ErrorSummary, "apps status update failed") {
		t.Fatalf("error summary = %q, want it to mention the completion failure", found.ErrorSummary)
	}
	if found.UnsignedObjectKey != "" || found.SignedTestObjectKey != "" {
		t.Fatalf("artifact keys should be cleared once the uploaded artifacts are rolled back: %+v", found)
	}
	unsignedObjectKey := artifactObjectKey(found, "unsigned", ".apk")
	if _, ok := storage.objects[unsignedObjectKey]; ok {
		t.Fatal("expected uploaded artifact to be rolled back when completion persistence fails")
	}

	app, appErr := appRepo.FindByID(task.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}
}

func TestHardeningWorker_ProcessNextWithoutSignedArtifactStillCompletes(t *testing.T) {
	database, w, repo, appRepo, storage, runner, scope := setupWorkerTest(t)
	runner.writeSigned = false
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "unsigned-only")

	processed, err := w.ProcessNext(context.Background())
	if err != nil {
		t.Fatalf("ProcessNext() error = %v", err)
	}
	if !processed {
		t.Fatal("processed = false, want true")
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	if found.Status != model.HardeningTaskStatusCompleted {
		t.Fatalf("task status = %s, want completed", found.Status)
	}
	if found.SignedTestObjectKey != "" {
		t.Fatalf("SignedTestObjectKey = %q, want empty", found.SignedTestObjectKey)
	}

	logs, logErr := repo.Logs(task.ID, repository.HardeningLogFilter{Limit: 50})
	if logErr != nil {
		t.Fatalf("Logs() error = %v", logErr)
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

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if app.Status != model.AppStatusCompleted {
		t.Fatalf("app status = %s, want completed", app.Status)
	}
}

func TestHardeningWorker_ProcessNextUploadFailureMarksTaskAndAppFailed(t *testing.T) {
	database, w, repo, appRepo, storage, runner, scope := setupWorkerTest(t)
	storage.putErr = errors.New("upload failed")
	storage.putFailAfter = 2
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "upload-fail")

	processed, err := w.ProcessNext(context.Background())
	if !processed {
		t.Fatal("processed = false, want true")
	}
	if !errors.Is(err, storage.putErr) {
		t.Fatalf("ProcessNext() error = %v, want %v", err, storage.putErr)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
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
	unsignedObjectKey := artifactObjectKey(found, "unsigned", ".apk")
	if _, ok := storage.objects[unsignedObjectKey]; ok {
		t.Fatal("expected unsigned artifact rollback after signed upload failure")
	}
	if _, ok := storage.objects[artifactObjectKey(found, "signed_test", ".apk")]; ok {
		t.Fatal("signed artifact should not upload after failure")
	}
	if len(storage.deleteCalls) != 1 || storage.deleteCalls[0] != unsignedObjectKey {
		t.Fatalf("delete calls = %+v, want [%s]", storage.deleteCalls, unsignedObjectKey)
	}

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}

	uploadStep, stepErr := repo.FindStep(task.ID, model.HardeningStepUploadArtifacts)
	if stepErr != nil {
		t.Fatalf("FindStep(upload) error = %v", stepErr)
	}
	if uploadStep.Status != model.HardeningStepStatusFailed {
		t.Fatalf("upload step status = %s, want failed", uploadStep.Status)
	}

	_ = runner
}

func TestHardeningWorker_ProcessNextUploadFailureRollsBackWithCanceledTaskContext(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	storage.putErr = context.Canceled
	storage.putFailAfter = 2
	storage.onPutFail = cancel
	storage.failDeleteOnCanceledContext = true
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "upload-cancel-rollback")

	processed, err := w.ProcessNext(ctx)
	if !processed {
		t.Fatal("processed = false, want true")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessNext() error = %v, want %v", err, context.Canceled)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	unsignedObjectKey := artifactObjectKey(found, "unsigned", ".apk")
	if _, ok := storage.objects[unsignedObjectKey]; ok {
		t.Fatal("expected unsigned artifact rollback even after task context cancellation")
	}
	if len(storage.deleteCalls) != 1 || storage.deleteCalls[0] != unsignedObjectKey {
		t.Fatalf("delete calls = %+v, want [%s]", storage.deleteCalls, unsignedObjectKey)
	}

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if found.Status != model.HardeningTaskStatusFailed || app.Status != model.AppStatusFailed {
		t.Fatalf("task/app status = %s/%s, want failed/failed", found.Status, app.Status)
	}
}

func TestHardeningWorker_ProcessNextCompletionFailureRollsBackUploadedArtifacts(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "completion-artifact-rollback")
	updateErr := errors.New("apps status update failed")
	registerWorkerAppUpdateFailureOnce(t, database, "worker-complete-artifact-rollback", updateErr)

	processed, err := w.ProcessNext(context.Background())
	if !processed {
		t.Fatal("processed = false, want true")
	}
	if !errors.Is(err, updateErr) {
		t.Fatalf("ProcessNext() error = %v, want %v", err, updateErr)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	unsignedObjectKey := artifactObjectKey(found, "unsigned", ".apk")
	signedObjectKey := artifactObjectKey(found, "signed_test", ".apk")
	if _, ok := storage.objects[unsignedObjectKey]; ok {
		t.Fatal("expected unsigned artifact rollback after completion transition failure")
	}
	if _, ok := storage.objects[signedObjectKey]; ok {
		t.Fatal("expected signed artifact rollback after completion transition failure")
	}
	if len(storage.deleteCalls) != 2 || storage.deleteCalls[0] != signedObjectKey || storage.deleteCalls[1] != unsignedObjectKey {
		t.Fatalf("delete calls = %+v, want [%s %s]", storage.deleteCalls, signedObjectKey, unsignedObjectKey)
	}

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if found.Status != model.HardeningTaskStatusFailed || app.Status != model.AppStatusFailed {
		t.Fatalf("task/app status = %s/%s, want failed/failed (must not get stuck in running when completion persistence fails)", found.Status, app.Status)
	}
}

func TestHardeningWorker_ProcessNextContextCancellationMarksTaskAndAppFailed(t *testing.T) {
	database, w, repo, appRepo, storage, runner, scope := setupWorkerTest(t)
	runner.blockOnCtx = true
	w.cfg.Timeout = 20 * time.Millisecond
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "ctx-timeout")

	processed, err := w.ProcessNext(context.Background())
	if !processed {
		t.Fatal("processed = false, want true")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ProcessNext() error = %v, want %v", err, context.DeadlineExceeded)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed", found.Status)
	}
	if !strings.Contains(found.ErrorSummary, context.DeadlineExceeded.Error()) {
		t.Fatalf("error summary = %q, want context deadline exceeded", found.ErrorSummary)
	}

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if app.Status != model.AppStatusFailed {
		t.Fatalf("app status = %s, want failed", app.Status)
	}
}

func TestHardeningWorker_ProcessNextRemovesTaskWorkDir(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	workRoot := t.TempDir()
	w.cfg.WorkDir = workRoot
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "cleanup-workdir")

	processed, err := w.ProcessNext(context.Background())
	if err != nil {
		t.Fatalf("ProcessNext() error = %v", err)
	}
	if !processed {
		t.Fatal("processed = false, want true")
	}

	workDir := filepath.Join(workRoot, task.TaskNo)
	if _, statErr := os.Stat(workDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("work dir stat error = %v, want %v", statErr, os.ErrNotExist)
	}
}

func TestHardeningWorker_RecoverRunningMarksTasksAndAppsFailed(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "recover")
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

func TestHardeningWorker_RecoverRunningCleansUpOrphanedArtifacts(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "recover-artifacts")
	if err := repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}

	// Simulate a crash that happened after the upload step succeeded (and
	// eagerly recorded the artifact keys via RecordArtifacts) but before the
	// task was marked completed: the objects genuinely exist in storage, and
	// the DB row still points at them.
	unsignedKey := artifactObjectKey(&task, "unsigned", ".apk")
	signedKey := artifactObjectKey(&task, "signed_test", ".apk")
	storage.objects[unsignedKey] = []byte("unsigned")
	storage.objects[signedKey] = []byte("signed")
	if err := repo.RecordArtifacts(task.ID, unsignedKey, 8, "unsigned-sha", signedKey, 6, "signed-sha"); err != nil {
		t.Fatalf("RecordArtifacts() error = %v", err)
	}

	if err := w.RecoverRunning(context.Background()); err != nil {
		t.Fatalf("RecoverRunning() error = %v", err)
	}

	found, err := repo.FindByID(task.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.Status != model.HardeningTaskStatusFailed {
		t.Fatalf("task status = %s, want failed", found.Status)
	}
	if found.UnsignedObjectKey != "" || found.SignedTestObjectKey != "" {
		t.Fatalf("artifact keys should be cleared after recovery: %+v", found)
	}

	if _, ok := storage.objects[unsignedKey]; ok {
		t.Fatal("expected orphaned unsigned artifact to be cleaned up on recovery")
	}
	if _, ok := storage.objects[signedKey]; ok {
		t.Fatal("expected orphaned signed artifact to be cleaned up on recovery")
	}
	if len(storage.deleteCalls) != 2 {
		t.Fatalf("delete calls = %+v, want 2 deletions", storage.deleteCalls)
	}
}

func TestHardeningWorker_RecoverRunningHonorsCanceledContext(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "recover-canceled")
	if err := repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := w.RecoverRunning(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RecoverRunning() error = %v, want %v", err, context.Canceled)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	if found.Status != model.HardeningTaskStatusRunning {
		t.Fatalf("task status = %s, want running", found.Status)
	}

	app, appErr := appRepo.FindByID(found.AppID)
	if appErr != nil {
		t.Fatalf("FindByID(app) error = %v", appErr)
	}
	if app.Status != model.AppStatusProcessing {
		t.Fatalf("app status = %s, want processing", app.Status)
	}
}

func TestHardeningWorker_RecoverRunningReturnsErrorWithoutDriftWhenAppUpdateFails(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "recover-rollback")
	if err := repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	updateErr := errors.New("apps status update failed")
	registerWorkerAppUpdateFailure(t, database, "worker-recover-app-update", updateErr)

	err := w.RecoverRunning(context.Background())
	if !errors.Is(err, updateErr) {
		t.Fatalf("RecoverRunning() error = %v, want %v", err, updateErr)
	}

	found, findErr := repo.FindByID(task.ID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v", findErr)
	}
	if found.Status != model.HardeningTaskStatusRunning {
		t.Fatalf("task status = %s, want running after rollback", found.Status)
	}
}

func TestHardeningWorker_StartReportsRecoverRunningError(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "start-recover-error")
	if err := repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	updateErr := errors.New("apps status update failed")
	registerWorkerAppUpdateFailure(t, database, "worker-start-recover-app-update", updateErr)

	errs := make(chan error, 1)
	w.cfg.OnError = func(err error) {
		errs <- err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx, 10*time.Millisecond)

	err := waitForWorkerError(t, errs)
	if !errors.Is(err, updateErr) {
		t.Fatalf("reported error = %v, want %v", err, updateErr)
	}
}

func TestHardeningWorker_StartReportsProcessNextError(t *testing.T) {
	database, w, repo, appRepo, storage, runner, scope := setupWorkerTest(t)
	runner.err = errors.New("engine crashed")
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "start-process-error")
	_ = task
	errs := make(chan error, 1)
	w.cfg.OnError = func(err error) {
		errs <- err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx, 10*time.Millisecond)

	err := waitForWorkerError(t, errs)
	if !errors.Is(err, runner.err) {
		t.Fatalf("reported error = %v, want %v", err, runner.err)
	}
}

func TestHardeningWorker_ReportAsyncErrorLogsWithoutOnErrorHook(t *testing.T) {
	_, w, _, _, _, _, _ := setupWorkerTest(t)

	var logBuf bytes.Buffer
	originalWriter := log.Writer()
	originalFlags := log.Flags()
	originalPrefix := log.Prefix()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	})

	reportErr := errors.New("default async error path")
	w.reportAsyncError(reportErr)

	got := logBuf.String()
	if !strings.Contains(got, reportErr.Error()) {
		t.Fatalf("log output = %q, want substring %q", got, reportErr.Error())
	}
}

func TestHardeningWorker_RunStepOutOfOrderFails(t *testing.T) {
	database, w, repo, appRepo, storage, _, scope := setupWorkerTest(t)
	task := createWorkerTask(t, database, repo, appRepo, storage, scope, "out-of-order")
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

func waitForWorkerError(t *testing.T, errs <-chan error) error {
	t.Helper()
	select {
	case err := <-errs:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker error")
		return nil
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
