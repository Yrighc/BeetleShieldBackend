package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

var (
	ErrHardeningAppNotFound      = errors.New("app not found")
	ErrHardeningTaskNotFound     = errors.New("hardening task not found")
	ErrHardeningActiveTaskExists = errors.New("app already has an active hardening task")
	ErrHardeningArtifactNotFound = errors.New("hardening artifact not found")
	ErrInvalidHardeningArtifact  = errors.New("invalid hardening artifact")
	ErrHardeningReportNotReady   = errors.New("hardening task not completed, report not available")
	ErrHardeningStrategyNotFound = errors.New("hardening strategy not found")
)

type DownloadURLProvider interface {
	PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error)
}

type CreateHardeningTaskInput struct {
	AppID            uint
	StrategyID       uint
	StrategyName     string
	StrategySnapshot *model.Strategy
	CreatedBy        uint
	IP               string
}

type HardeningTaskDetail struct {
	Task       model.HardeningTask   `json:"task"`
	Steps      []model.HardeningStep `json:"steps"`
	RecentLogs []model.HardeningLog  `json:"recentLogs"`
}

type HardeningService struct {
	hardeningRepo   *repository.HardeningRepository
	appRepo         *repository.AppRepository
	strategyService *StrategyService
	storage         DownloadURLProvider
	defaultVMPRules string
	auditService    *AuditService
	engineVersion   string
}

func NewHardeningService(
	hardeningRepo *repository.HardeningRepository,
	appRepo *repository.AppRepository,
	strategyService *StrategyService,
	storage DownloadURLProvider,
	defaultVMPRules string,
	auditService *AuditService,
	engineVersion string,
) *HardeningService {
	return &HardeningService{
		hardeningRepo:   hardeningRepo,
		appRepo:         appRepo,
		strategyService: strategyService,
		storage:         storage,
		defaultVMPRules: defaultVMPRules,
		auditService:    auditService,
		engineVersion:   engineVersion,
	}
}

func (s *HardeningService) Create(ctx context.Context, input CreateHardeningTaskInput) (detail *HardeningTaskDetail, err error) {
	defer func() {
		if err != nil {
			s.auditService.Record(RecordAuditInput{
				ActorUserID: input.CreatedBy,
				Action:      model.AuditActionHardeningCreate,
				TargetType:  "app",
				TargetID:    input.AppID,
				Detail:      "创建加固任务失败 - " + err.Error(),
				IP:          input.IP,
				Success:     false,
			})
		}
	}()
	_ = ctx

	app, err := s.appRepo.FindByID(input.AppID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningAppNotFound
		}
		return nil, err
	}

	strategy := model.Strategy{}
	strategyName := input.StrategyName
	if input.StrategyID > 0 {
		resolved, resolvedName, err := s.strategyService.ResolveForHardening(input.StrategyID)
		if err != nil {
			if errors.Is(err, ErrStrategyNotFound) {
				return nil, ErrHardeningStrategyNotFound
			}
			return nil, err
		}
		strategy = *resolved
		strategyName = resolvedName
	} else if input.StrategySnapshot != nil {
		strategy = *input.StrategySnapshot
	} else {
		current, currentName, err := s.strategyService.ResolveForHardening(0)
		if err != nil {
			return nil, err
		}
		strategy = *current
		strategyName = currentName
	}

	if strategyName == "" {
		strategyName = DefaultStrategyName
	}
	strategy.VMPRulesText = NormalizeVMPRules(strategy.VMPRulesText, s.defaultVMPRules)

	task := &model.HardeningTask{
		TaskNo:           generateHardeningTaskNo(time.Now()),
		AppID:            app.ID,
		Status:           model.HardeningTaskStatusQueued,
		StrategyName:     strategyName,
		StrategySnapshot: strategy,
		CreatedBy:        input.CreatedBy,
	}

	if err := s.hardeningRepo.CreateTaskWithStepsForApp(task, model.AppStatusProcessing); err != nil {
		if errors.Is(err, repository.ErrActiveHardeningTaskExists) {
			return nil, ErrHardeningActiveTaskExists
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningAppNotFound
		}
		return nil, err
	}

	s.auditService.Record(RecordAuditInput{
		ActorUserID: input.CreatedBy,
		Action:      model.AuditActionHardeningCreate,
		TargetType:  "hardening_task",
		TargetID:    task.ID,
		Detail:      app.Name + " / " + task.TaskNo,
		IP:          input.IP,
		Success:     true,
	})
	return s.Get(task.ID)
}

func (s *HardeningService) List(filter repository.HardeningListFilter) ([]model.HardeningTask, int64, error) {
	return s.hardeningRepo.List(filter)
}

func (s *HardeningService) Get(id uint) (*HardeningTaskDetail, error) {
	task, err := s.hardeningRepo.FindByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningTaskNotFound
		}
		return nil, err
	}

	steps, err := s.hardeningRepo.Steps(id)
	if err != nil {
		return nil, err
	}
	logs, err := s.hardeningRepo.Logs(id, repository.HardeningLogFilter{Limit: 20})
	if err != nil {
		return nil, err
	}

	return &HardeningTaskDetail{
		Task:       *task,
		Steps:      steps,
		RecentLogs: logs,
	}, nil
}

func (s *HardeningService) Logs(taskID uint, filter repository.HardeningLogFilter) ([]model.HardeningLog, error) {
	if _, err := s.hardeningRepo.FindByID(taskID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningTaskNotFound
		}
		return nil, err
	}
	return s.hardeningRepo.Logs(taskID, filter)
}

func (s *HardeningService) History(appID uint) ([]model.HardeningTask, error) {
	if _, err := s.appRepo.FindByID(appID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningAppNotFound
		}
		return nil, err
	}
	return s.hardeningRepo.RecentByApp(appID, 5)
}

func (s *HardeningService) DownloadURL(ctx context.Context, taskID uint, artifact string, actorUserID uint, ip string) (string, error) {
	task, err := s.hardeningRepo.FindByID(taskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrHardeningTaskNotFound
		}
		return "", err
	}

	var objectKey string
	switch artifact {
	case "", "unsigned":
		objectKey = task.UnsignedObjectKey
	case "signed_test":
		objectKey = task.SignedTestObjectKey
	default:
		return "", ErrInvalidHardeningArtifact
	}
	if objectKey == "" {
		return "", ErrHardeningArtifactNotFound
	}

	downloadURL, err := s.storage.PresignedDownloadURL(ctx, objectKey, 15*time.Minute)
	if err != nil {
		return "", err
	}
	artifactLabel := artifact
	if artifactLabel == "" {
		artifactLabel = "unsigned"
	}
	s.auditService.Record(RecordAuditInput{
		ActorUserID: actorUserID,
		Action:      model.AuditActionHardeningDownload,
		TargetType:  "hardening_task",
		TargetID:    task.ID,
		Detail:      task.App.Name + " / " + task.TaskNo + " / " + artifactLabel,
		IP:          ip,
		Success:     true,
	})
	return downloadURL, nil
}

func (s *HardeningService) GetReport(taskID uint) (*HardeningReport, error) {
	task, err := s.hardeningRepo.FindByID(taskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningTaskNotFound
		}
		return nil, err
	}
	if task.Status != model.HardeningTaskStatusCompleted {
		return nil, ErrHardeningReportNotReady
	}

	report := BuildHardeningReport(*task, s.engineVersion)
	return &report, nil
}

func generateHardeningTaskNo(now time.Time) string {
	return fmt.Sprintf("TASK-%s-%d", now.Format("20060102"), now.UnixNano())
}
