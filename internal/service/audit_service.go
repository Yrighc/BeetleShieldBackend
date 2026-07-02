package service

import (
	"log"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type RecordAuditInput struct {
	ActorUserID uint
	ActorEmail  string
	Action      model.AuditAction
	TargetType  string
	TargetID    uint
	Detail      string
	IP          string
	Success     bool
}

type AuditService struct {
	auditRepo *repository.AuditRepository
}

func NewAuditService(auditRepo *repository.AuditRepository) *AuditService {
	return &AuditService{auditRepo: auditRepo}
}

func (s *AuditService) Record(input RecordAuditInput) {
	if s == nil || s.auditRepo == nil {
		log.Printf("audit: failed to record %s: audit repository is not configured", input.Action)
		return
	}

	entry := &model.AuditLog{
		ActorUserID: input.ActorUserID,
		ActorEmail:  input.ActorEmail,
		Action:      input.Action,
		TargetType:  input.TargetType,
		TargetID:    input.TargetID,
		Detail:      input.Detail,
		IP:          input.IP,
		Success:     input.Success,
	}
	if err := s.auditRepo.Record(entry); err != nil {
		log.Printf("audit: failed to record %s: %v", input.Action, err)
	}
}

func (s *AuditService) List(filter repository.AuditListFilter) ([]model.AuditLog, int64, error) {
	return s.auditRepo.List(filter)
}
