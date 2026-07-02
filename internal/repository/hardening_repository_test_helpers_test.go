package repository

import (
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

// The functions below existed in the production HardeningRepository but had
// no production callers (CreateTaskWithStepsForApp/CompleteTaskForApp/
// FailTaskForApp superseded them). They are kept here, test-only, verbatim,
// so the many existing table-driven tests in hardening_repository_test.go
// that exercise them keep working without needing a rewrite for this cleanup.

func (r *HardeningRepository) CreateTaskWithSteps(task *model.HardeningTask) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		return createTaskWithDefaultSteps(tx, task)
	})
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
