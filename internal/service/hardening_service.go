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
)

type DownloadURLProvider interface {
	PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error)
}

type CreateHardeningTaskInput struct {
	AppID                    uint
	StrategyName             string
	StrategySnapshot         *model.Strategy
	VMPRulesText             string
	EnableFileIntegrityCheck bool
	EnableProxyDetect        bool
	CreatedBy                uint
	IP                       string
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
}

func NewHardeningService(
	hardeningRepo *repository.HardeningRepository,
	appRepo *repository.AppRepository,
	strategyService *StrategyService,
	storage DownloadURLProvider,
	defaultVMPRules string,
	auditService *AuditService,
) *HardeningService {
	return &HardeningService{
		hardeningRepo:   hardeningRepo,
		appRepo:         appRepo,
		strategyService: strategyService,
		storage:         storage,
		defaultVMPRules: defaultVMPRules,
		auditService:    auditService,
	}
}

func (s *HardeningService) Create(ctx context.Context, input CreateHardeningTaskInput) (*HardeningTaskDetail, error) {
	_ = ctx

	app, err := s.appRepo.FindByID(input.AppID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHardeningAppNotFound
		}
		return nil, err
	}

	strategy := model.Strategy{}
	if input.StrategySnapshot != nil {
		strategy = *input.StrategySnapshot
	} else {
		current, err := s.strategyService.GetCurrent()
		if err != nil {
			return nil, err
		}
		strategy = *current
	}

	strategyName := input.StrategyName
	if strategyName == "" {
		strategyName = DefaultStrategyName
	}

	task := &model.HardeningTask{
		TaskNo:                   generateHardeningTaskNo(time.Now()),
		AppID:                    app.ID,
		Status:                   model.HardeningTaskStatusQueued,
		StrategyName:             strategyName,
		StrategySnapshot:         strategy,
		VMPRulesText:             NormalizeVMPRules(input.VMPRulesText, s.defaultVMPRules),
		EnableFileIntegrityCheck: input.EnableFileIntegrityCheck,
		EnableProxyDetect:        input.EnableProxyDetect,
		CreatedBy:                input.CreatedBy,
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

	s.recordAudit(RecordAuditInput{
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
	s.recordAudit(RecordAuditInput{
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

func generateHardeningTaskNo(now time.Time) string {
	return fmt.Sprintf("TASK-%s-%d", now.Format("20060102"), now.UnixNano())
}

func (s *HardeningService) recordAudit(input RecordAuditInput) {
	if s.auditService != nil {
		s.auditService.Record(input)
	}
}
