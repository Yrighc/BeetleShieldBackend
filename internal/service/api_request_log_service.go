package service

import (
	"log"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type RecordAPIRequestInput struct {
	Method      string
	Path        string
	Status      int
	LatencyMS   int64
	ClientIP    string
	ActorUserID uint
}

type APIRequestLogService struct {
	repo *repository.APIRequestLogRepository
}

func NewAPIRequestLogService(repo *repository.APIRequestLogRepository) *APIRequestLogService {
	return &APIRequestLogService{repo: repo}
}

// Record is fire-and-forget, same contract as AuditService.Record: it runs
// after the response has already been written (from the request-log
// middleware's deferred call), so there is nothing meaningful to propagate
// an error to even if we wanted to — a write failure is logged and dropped.
func (s *APIRequestLogService) Record(input RecordAPIRequestInput) {
	if s == nil || s.repo == nil {
		log.Printf("api request log: failed to record %s %s: repository is not configured", input.Method, input.Path)
		return
	}
	entry := &model.APIRequestLog{
		Method:      input.Method,
		Path:        input.Path,
		Status:      input.Status,
		LatencyMS:   input.LatencyMS,
		ClientIP:    input.ClientIP,
		ActorUserID: input.ActorUserID,
	}
	if err := s.repo.Record(entry); err != nil {
		log.Printf("api request log: failed to record %s %s: %v", input.Method, input.Path, err)
	}
}

func (s *APIRequestLogService) List(filter repository.APIRequestLogListFilter) ([]model.APIRequestLog, int64, error) {
	return s.repo.List(filter)
}
