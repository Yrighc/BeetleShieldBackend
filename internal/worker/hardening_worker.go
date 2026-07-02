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

func NewHardeningWorker(repo *repository.HardeningRepository, appRepo *repository.AppRepository, storage ObjectStorage, runner EngineRunner, cfg HardeningWorkerConfig) *HardeningWorker {
	_ = appRepo
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
	ids, err := w.repo.RecoverRunningTasks("服务重启导致任务中断")
	if err != nil {
		return err
	}
	_ = ids
	return nil
}

func (w *HardeningWorker) ProcessNext(ctx context.Context) (bool, error) {
	task, err := w.repo.NextQueuedTask()
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}

	if err := w.repo.MarkTaskRunning(task.ID, time.Now()); err != nil {
		return false, err
	}

	if err := w.runTask(ctx, task); err != nil {
		now := time.Now()
		markErr := w.repo.FailTaskForApp(task.ID, err.Error(), now)
		return true, errors.Join(err, markErr)
	}

	return true, nil
}

func (w *HardeningWorker) Start(ctx context.Context, interval time.Duration) {
	go func() {
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
		return w.uploadArtifacts(taskCtx, unsigned, signed)
	}); err != nil {
		return err
	}

	now := time.Now()
	if err := w.repo.CompleteTaskForApp(task.ID, unsigned.ObjectKey, unsigned.Size, unsigned.SHA256, signed.ObjectKey, signed.Size, signed.SHA256, now); err != nil {
		return err
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

func (w *HardeningWorker) uploadArtifact(ctx context.Context, artifact service.ArtifactInfo) error {
	file, err := os.Open(artifact.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	return w.storage.PutObject(ctx, artifact.ObjectKey, file, artifact.Size, "application/octet-stream")
}

func (w *HardeningWorker) uploadArtifacts(ctx context.Context, artifacts ...service.ArtifactInfo) error {
	uploadedKeys := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Path == "" {
			continue
		}
		if err := w.uploadArtifact(ctx, artifact); err != nil {
			return errors.Join(err, w.rollbackArtifacts(ctx, uploadedKeys))
		}
		uploadedKeys = append(uploadedKeys, artifact.ObjectKey)
	}
	return nil
}

func (w *HardeningWorker) rollbackArtifacts(ctx context.Context, objectKeys []string) error {
	var rollbackErr error
	for i := len(objectKeys) - 1; i >= 0; i-- {
		rollbackErr = errors.Join(rollbackErr, w.storage.DeleteObject(ctx, objectKeys[i]))
	}
	return rollbackErr
}

func artifactObjectKey(task *model.HardeningTask, kind string, ext string) string {
	return fmt.Sprintf("%s/hardening/%s/%s%s", task.App.PackageName, task.TaskNo, kind, ext)
}
