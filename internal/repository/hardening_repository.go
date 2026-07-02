package repository

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"beetleshield-backend/internal/model"
)

type HardeningListFilter struct {
	Status   string
	AppID    uint
	Search   string
	Page     int
	PageSize int
}

type HardeningLogFilter struct {
	StepKey model.HardeningStepKey
	AfterID uint
	Limit   int
}

type HardeningRepository struct {
	db *gorm.DB
}

var ErrActiveHardeningTaskExists = errors.New("active hardening task already exists")

func NewHardeningRepository(db *gorm.DB) *HardeningRepository {
	return &HardeningRepository{db: db}
}

var defaultHardeningSteps = []model.HardeningStep{
	{StepKey: model.HardeningStepPrepareInput, Name: "准备输入", SortOrder: 1, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepParsePackage, Name: "解析包体", SortOrder: 2, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepApplyStrategy, Name: "应用策略", SortOrder: 3, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepRunEngine, Name: "执行加固", SortOrder: 4, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepCollectArtifacts, Name: "收集产物", SortOrder: 5, Status: model.HardeningStepStatusWaiting},
	{StepKey: model.HardeningStepUploadArtifacts, Name: "上传产物", SortOrder: 6, Status: model.HardeningStepStatusWaiting},
}

func requireUpdatedRow(result *gorm.DB) error {
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *HardeningRepository) CreateTaskWithSteps(task *model.HardeningTask) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		return createTaskWithDefaultSteps(tx, task)
	})
}

func (r *HardeningRepository) CreateTaskWithStepsForApp(task *model.HardeningTask, appStatus model.AppStatus) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var app model.App
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&app, task.AppID).Error; err != nil {
			return err
		}

		var count int64
		if err := tx.Model(&model.HardeningTask{}).
			Where("app_id = ? AND status IN ?", task.AppID, []model.HardeningTaskStatus{
				model.HardeningTaskStatusQueued,
				model.HardeningTaskStatusRunning,
			}).
			Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrActiveHardeningTaskExists
		}

		if err := createTaskWithDefaultSteps(tx, task); err != nil {
			return err
		}

		return requireUpdatedRow(tx.Model(&model.App{}).
			Where("id = ?", task.AppID).
			Update("status", appStatus))
	})
}

func createTaskWithDefaultSteps(tx *gorm.DB, task *model.HardeningTask) error {
	if err := tx.Create(task).Error; err != nil {
		return err
	}
	for _, template := range defaultHardeningSteps {
		step := template
		step.TaskID = task.ID
		if err := tx.Create(&step).Error; err != nil {
			return err
		}
	}
	return nil
}

func (r *HardeningRepository) HasActiveTaskForApp(appID uint) (bool, error) {
	var count int64
	err := r.db.Model(&model.HardeningTask{}).
		Where("app_id = ? AND status IN ?", appID, []model.HardeningTaskStatus{
			model.HardeningTaskStatusQueued,
			model.HardeningTaskStatusRunning,
		}).
		Count(&count).Error
	return count > 0, err
}

func (r *HardeningRepository) NextQueuedTask() (*model.HardeningTask, error) {
	var task model.HardeningTask
	if err := r.db.Preload("App").
		Where("status = ?", model.HardeningTaskStatusQueued).
		Order("created_at ASC, id ASC").
		First(&task).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *HardeningRepository) MarkTaskRunning(taskID uint, startedAt time.Time) error {
	return requireUpdatedRow(r.db.Model(&model.HardeningTask{}).
		Where("id = ? AND status = ?", taskID, model.HardeningTaskStatusQueued).
		Updates(map[string]interface{}{
			"status":     model.HardeningTaskStatusRunning,
			"started_at": startedAt,
		}))
}

func (r *HardeningRepository) MarkTaskCompleted(taskID uint, unsignedKey string, unsignedSize int64, unsignedSHA string, signedKey string, signedSize int64, signedSHA string, finishedAt time.Time) error {
	return requireUpdatedRow(r.db.Model(&model.HardeningTask{}).
		Where("id = ? AND status = ?", taskID, model.HardeningTaskStatusRunning).
		Updates(map[string]interface{}{
			"status":                 model.HardeningTaskStatusCompleted,
			"unsigned_object_key":    unsignedKey,
			"unsigned_file_size":     unsignedSize,
			"unsigned_sha256":        unsignedSHA,
			"signed_test_object_key": signedKey,
			"signed_test_file_size":  signedSize,
			"signed_test_sha256":     signedSHA,
			"finished_at":            finishedAt,
			"error_summary":          "",
		}))
}

func (r *HardeningRepository) MarkTaskFailed(taskID uint, summary string, finishedAt time.Time) error {
	return requireUpdatedRow(r.db.Model(&model.HardeningTask{}).
		Where("id = ? AND status = ?", taskID, model.HardeningTaskStatusRunning).
		Updates(map[string]interface{}{
			"status":        model.HardeningTaskStatusFailed,
			"error_summary": summary,
			"finished_at":   finishedAt,
		}))
}

func (r *HardeningRepository) RecoverRunningTasks(summary string) ([]uint, error) {
	var tasks []model.HardeningTask
	if err := r.db.Where("status = ?", model.HardeningTaskStatusRunning).Find(&tasks).Error; err != nil {
		return nil, err
	}

	ids := make([]uint, 0, len(tasks))
	for _, task := range tasks {
		ids = append(ids, task.ID)
	}
	if len(ids) == 0 {
		return ids, nil
	}

	now := time.Now()
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.HardeningTask{}).
			Where("id IN ?", ids).
			Updates(map[string]interface{}{
				"status":        model.HardeningTaskStatusFailed,
				"error_summary": summary,
				"finished_at":   now,
			}).Error; err != nil {
			return err
		}

		return tx.Model(&model.HardeningStep{}).
			Where("task_id IN ? AND status = ?", ids, model.HardeningStepStatusRunning).
			Updates(map[string]interface{}{
				"status":        model.HardeningStepStatusFailed,
				"error_message": summary,
				"finished_at":   now,
			}).Error
	})
	return ids, err
}

func (r *HardeningRepository) List(filter HardeningListFilter) ([]model.HardeningTask, int64, error) {
	query := r.db.Model(&model.HardeningTask{}).
		Joins("LEFT JOIN apps ON apps.id = hardening_tasks.app_id")

	if filter.Status != "" {
		query = query.Where("hardening_tasks.status = ?", filter.Status)
	}
	if filter.AppID != 0 {
		query = query.Where("hardening_tasks.app_id = ?", filter.AppID)
	}
	if filter.Search != "" {
		like := "%" + filter.Search + "%"
		query = query.Where(
			"hardening_tasks.task_no ILIKE ? OR apps.name ILIKE ? OR apps.package_name ILIKE ?",
			like, like, like,
		)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 10
	}

	var tasks []model.HardeningTask
	err := query.Preload("App").
		Order("hardening_tasks.created_at DESC, hardening_tasks.id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&tasks).Error
	return tasks, total, err
}

func (r *HardeningRepository) FindByID(id uint) (*model.HardeningTask, error) {
	var task model.HardeningTask
	if err := r.db.Preload("App").First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *HardeningRepository) RecentByApp(appID uint, limit int) ([]model.HardeningTask, error) {
	if limit < 1 {
		limit = 5
	}

	var tasks []model.HardeningTask
	err := r.db.Preload("App").
		Where("app_id = ?", appID).
		Order("created_at DESC, id DESC").
		Limit(limit).
		Find(&tasks).Error
	return tasks, err
}

func (r *HardeningRepository) Steps(taskID uint) ([]model.HardeningStep, error) {
	var steps []model.HardeningStep
	err := r.db.Where("task_id = ?", taskID).Order("sort_order ASC").Find(&steps).Error
	return steps, err
}

func (r *HardeningRepository) FindStep(taskID uint, key model.HardeningStepKey) (*model.HardeningStep, error) {
	var step model.HardeningStep
	if err := r.db.Where("task_id = ? AND step_key = ?", taskID, key).First(&step).Error; err != nil {
		return nil, err
	}
	return &step, nil
}

func (r *HardeningRepository) StartStep(stepID uint, startedAt time.Time) error {
	return requireUpdatedRow(r.db.Model(&model.HardeningStep{}).
		Where("id = ? AND status = ?", stepID, model.HardeningStepStatusWaiting).
		Updates(map[string]interface{}{
			"status":      model.HardeningStepStatusRunning,
			"started_at":  startedAt,
			"finished_at": nil,
		}))
}

func (r *HardeningRepository) FinishStepSuccess(stepID uint, finishedAt time.Time) error {
	return requireUpdatedRow(r.db.Model(&model.HardeningStep{}).
		Where("id = ? AND status = ?", stepID, model.HardeningStepStatusRunning).
		Updates(map[string]interface{}{
			"status":        model.HardeningStepStatusSuccess,
			"finished_at":   finishedAt,
			"error_message": "",
		}))
}

func (r *HardeningRepository) FinishStepFailed(stepID uint, message string, finishedAt time.Time) error {
	return requireUpdatedRow(r.db.Model(&model.HardeningStep{}).
		Where("id = ? AND status = ?", stepID, model.HardeningStepStatusRunning).
		Updates(map[string]interface{}{
			"status":        model.HardeningStepStatusFailed,
			"finished_at":   finishedAt,
			"error_message": message,
		}))
}

func (r *HardeningRepository) AppendLog(log *model.HardeningLog) error {
	return r.db.Create(log).Error
}

func (r *HardeningRepository) Logs(taskID uint, filter HardeningLogFilter) ([]model.HardeningLog, error) {
	query := r.db.Model(&model.HardeningLog{}).
		Where("hardening_logs.task_id = ?", taskID)

	if filter.AfterID != 0 {
		query = query.Where("hardening_logs.id > ?", filter.AfterID)
	}
	if filter.StepKey != "" {
		query = query.Joins("JOIN hardening_steps ON hardening_steps.id = hardening_logs.step_id").
			Where("hardening_steps.step_key = ?", filter.StepKey)
	}

	limit := filter.Limit
	if limit < 1 || limit > 500 {
		limit = 200
	}

	var logs []model.HardeningLog
	err := query.Order("hardening_logs.id ASC").Limit(limit).Find(&logs).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return []model.HardeningLog{}, nil
	}
	return logs, err
}
