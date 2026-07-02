package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type ObjectStorage interface {
	GetObjectToFile(ctx context.Context, objectKey string, destinationPath string) error
	PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string) error
	DeleteObject(ctx context.Context, objectKey string) error
}

type HardeningWorkerConfig struct {
	JarPath         string
	WorkDir         string
	DefaultVMPRules string
	Timeout         time.Duration
	OnError         func(error)
}

type HardeningWorker struct {
	repo    *repository.HardeningRepository
	storage ObjectStorage
	runner  EngineRunner
	cfg     HardeningWorkerConfig
}

func NewHardeningWorker(repo *repository.HardeningRepository, storage ObjectStorage, runner EngineRunner, cfg HardeningWorkerConfig) *HardeningWorker {
	return &HardeningWorker{
		repo:    repo,
		storage: storage,
		runner:  runner,
		cfg:     cfg,
	}
}

func (w *HardeningWorker) RecoverRunning(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tasks, err := w.repo.RecoverRunningTasks("服务重启导致任务中断")
	if err != nil {
		return err
	}
	w.cleanupRecoveredArtifacts(tasks)
	return nil
}

// cleanupRecoveredArtifacts best-effort deletes any artifact objects a
// crashed task had already uploaded (see RecordArtifacts) before the process
// died. Deletion failures are logged, not returned: the DB rows have already
// been marked failed with their artifact fields cleared, so a leaked object
// left in MinIO after a log warning is preferable to blocking the whole
// recovery pass on an object store that might be unavailable right after a
// restart.
func (w *HardeningWorker) cleanupRecoveredArtifacts(tasks []model.HardeningTask) {
	if len(tasks) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, task := range tasks {
		for _, key := range []string{task.UnsignedObjectKey, task.SignedTestObjectKey} {
			if key == "" {
				continue
			}
			if err := w.storage.DeleteObject(ctx, key); err != nil {
				log.Printf("hardening worker: failed to clean up orphaned artifact %q for task %d: %v", key, task.ID, err)
			}
		}
	}
}

func (w *HardeningWorker) ProcessNext(ctx context.Context) (bool, error) {
	task, err := w.repo.NextQueuedTask()
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	if task == nil {
		return false, nil
	}

	if err := w.repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		return false, err
	}

	if err := w.runTask(ctx, task); err != nil {
		// Always mark the task failed, even if the failure happened while
		// persisting a successful completion (CompleteTaskForApp): GORM wraps
		// that write in a transaction, so an error there means it rolled back
		// and the task is genuinely still "running" — not in some ambiguous
		// state. Leaving it "running" here would make it invisible to both
		// NextQueuedTask (only selects "queued") and the once-at-startup
		// crash recovery pass, stuck until a manual restart.
		now := time.Now()
		markErr := w.repo.FailTaskForApp(task.ID, err.Error(), now)
		return true, errors.Join(err, markErr)
	}

	return true, nil
}

// Start launches the worker loop in a goroutine and returns a channel that is
// closed once the loop has actually stopped, so callers doing graceful
// shutdown can wait for in-flight work to finish instead of exiting the
// process out from under it.
func (w *HardeningWorker) Start(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)

		if err := w.RecoverRunning(ctx); err != nil && ctx.Err() == nil {
			w.reportAsyncError(err)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if _, err := w.ProcessNext(ctx); err != nil && ctx.Err() == nil {
				w.reportAsyncError(err)
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func (w *HardeningWorker) reportAsyncError(err error) {
	if err == nil {
		return
	}
	if w.cfg.OnError != nil {
		w.cfg.OnError(err)
		return
	}
	log.Printf("hardening worker async error: %v", err)
}

func (w *HardeningWorker) runTask(ctx context.Context, task *model.HardeningTask) (err error) {
	timeout := w.cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Minute
	}

	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	workDir := filepath.Join(w.cfg.WorkDir, task.TaskNo)
	ext := filepath.Ext(task.App.ObjectKey)
	if ext == "" {
		ext = ".apk"
	}

	inputPath := filepath.Join(workDir, "input"+ext)
	outputPath := filepath.Join(workDir, "output"+ext)
	rulesPath := filepath.Join(workDir, "vmp-rules.txt")

	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}
	defer func() {
		if cleanupErr := os.RemoveAll(workDir); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	if err := w.runStep(task.ID, model.HardeningStepPrepareInput, func(step *model.HardeningStep) error {
		if err := w.storage.GetObjectToFile(taskCtx, task.App.ObjectKey, inputPath); err != nil {
			return err
		}
		rules := service.NormalizeVMPRules(task.VMPRulesText, w.cfg.DefaultVMPRules)
		return os.WriteFile(rulesPath, []byte(rules), 0o600)
	}); err != nil {
		return err
	}

	if err := w.runStep(task.ID, model.HardeningStepParsePackage, func(step *model.HardeningStep) error {
		return w.log(task.ID, &step.ID, model.HardeningLogLevelInfo, fmt.Sprintf("应用包名: %s, 版本: %s", task.App.PackageName, task.App.Version))
	}); err != nil {
		return err
	}

	command := service.BuildDPTCommand(service.EngineCommandInput{
		JavaBin:                  "java",
		JarPath:                  w.cfg.JarPath,
		InputPath:                inputPath,
		OutputPath:               outputPath,
		RulesPath:                rulesPath,
		Strategy:                 task.StrategySnapshot,
		EnableFileIntegrityCheck: task.EnableFileIntegrityCheck,
		EnableProxyDetect:        task.EnableProxyDetect,
	})

	if err := w.runStep(task.ID, model.HardeningStepApplyStrategy, func(step *model.HardeningStep) error {
		return w.log(task.ID, &step.ID, model.HardeningLogLevelInfo, "引擎命令: "+strings.Join(command, " "))
	}); err != nil {
		return err
	}

	if err := w.runStep(task.ID, model.HardeningStepRunEngine, func(step *model.HardeningStep) error {
		return w.runner.Run(taskCtx, EngineRunRequest{
			Command: command,
			WorkDir: workDir,
		}, func(level model.HardeningLogLevel, line string) {
			_ = w.log(task.ID, &step.ID, level, line)
		})
	}); err != nil {
		return err
	}

	var unsigned service.ArtifactInfo
	var signed service.ArtifactInfo
	var uploadedKeys []string
	defer func() {
		if err != nil && len(uploadedKeys) > 0 {
			err = errors.Join(err, w.rollbackArtifacts(uploadedKeys))
		}
	}()
	if err := w.runStep(task.ID, model.HardeningStepCollectArtifacts, func(step *model.HardeningStep) error {
		sum, size, err := service.SHA256File(outputPath)
		if err != nil {
			return fmt.Errorf("未生成未签名加固产物")
		}
		if size <= 0 {
			return fmt.Errorf("未签名加固产物为空")
		}
		unsigned = service.ArtifactInfo{
			Path:      outputPath,
			ObjectKey: artifactObjectKey(task, "unsigned", ext),
			Size:      size,
			SHA256:    sum,
		}

		signedPath := service.SignedTestArtifactPath(outputPath)
		if sum, size, err := service.SHA256File(signedPath); err == nil && size > 0 {
			signed = service.ArtifactInfo{
				Path:      signedPath,
				ObjectKey: artifactObjectKey(task, "signed_test", ext),
				Size:      size,
				SHA256:    sum,
			}
		} else {
			_ = w.log(task.ID, &step.ID, model.HardeningLogLevelWarn, "未发现测试签名产物")
		}
		return nil
	}); err != nil {
		return err
	}

	if err := w.runStep(task.ID, model.HardeningStepUploadArtifacts, func(step *model.HardeningStep) error {
		keys, uploadErr := w.uploadArtifacts(taskCtx, unsigned, signed)
		uploadedKeys = keys
		if uploadErr != nil {
			return uploadErr
		}
		// Record the uploaded object keys as soon as they exist, before the
		// task is marked completed. If the process crashes between here and
		// CompleteTaskForApp below, the DB row still points at real objects
		// in MinIO, so the crash-recovery pass (RecoverRunning) can find and
		// clean them up instead of leaking them forever.
		return w.repo.RecordArtifacts(task.ID, unsigned.ObjectKey, unsigned.Size, unsigned.SHA256, signed.ObjectKey, signed.Size, signed.SHA256)
	}); err != nil {
		return err
	}

	now := time.Now()
	if err := w.repo.CompleteTaskForApp(task.ID, unsigned.ObjectKey, unsigned.Size, unsigned.SHA256, signed.ObjectKey, signed.Size, signed.SHA256, now); err != nil {
		return fmt.Errorf("persist task completion: %w", err)
	}

	return nil
}

func (w *HardeningWorker) runStep(taskID uint, key model.HardeningStepKey, fn func(*model.HardeningStep) error) error {
	step, err := w.repo.FindStep(taskID, key)
	if err != nil {
		return err
	}

	now := time.Now()
	if err := w.repo.StartStep(step.ID, now); err != nil {
		return err
	}

	if err := fn(step); err != nil {
		_ = w.repo.FinishStepFailed(step.ID, err.Error(), time.Now())
		_ = w.log(taskID, &step.ID, model.HardeningLogLevelError, err.Error())
		return err
	}

	return w.repo.FinishStepSuccess(step.ID, time.Now())
}

func (w *HardeningWorker) log(taskID uint, stepID *uint, level model.HardeningLogLevel, message string) error {
	return w.repo.AppendLog(&model.HardeningLog{
		TaskID:  taskID,
		StepID:  stepID,
		Level:   level,
		Message: message,
	})
}

func (w *HardeningWorker) uploadArtifacts(ctx context.Context, artifacts ...service.ArtifactInfo) ([]string, error) {
	uploadedKeys := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Path == "" {
			continue
		}
		if err := w.uploadOne(ctx, artifact); err != nil {
			return uploadedKeys, err
		}
		uploadedKeys = append(uploadedKeys, artifact.ObjectKey)
	}
	return uploadedKeys, nil
}

func (w *HardeningWorker) uploadOne(ctx context.Context, artifact service.ArtifactInfo) error {
	file, err := os.Open(artifact.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	return w.storage.PutObject(ctx, artifact.ObjectKey, file, artifact.Size, "application/octet-stream")
}

func (w *HardeningWorker) rollbackArtifacts(objectKeys []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var rollbackErr error
	for i := len(objectKeys) - 1; i >= 0; i-- {
		rollbackErr = errors.Join(rollbackErr, w.storage.DeleteObject(ctx, objectKeys[i]))
	}
	return rollbackErr
}

func artifactObjectKey(task *model.HardeningTask, kind string, ext string) string {
	return fmt.Sprintf("%s/hardening/%s/%s%s", sanitizeObjectKeySegment(task.App.PackageName), task.TaskNo, kind, ext)
}

// sanitizeObjectKeySegment strips characters that would let a package name
// escape its intended position in a MinIO object key (e.g. "../" path
// traversal, or a leading "/" turning a relative key absolute). Package
// names are attacker-controlled: they come from an uploaded APK's manifest
// or a manual form field, not from a trusted source.
func sanitizeObjectKeySegment(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "..", "_")
	if s == "" {
		return "_"
	}
	return s
}
