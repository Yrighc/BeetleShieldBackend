package service_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func setupAuditService(t *testing.T) (*service.AuditService, *gorm.DB, string, uint) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	marker := fmt.Sprintf("audit-service-%d", time.Now().UnixNano())
	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 200_000)
	t.Cleanup(func() {
		database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
	})
	auditRepo := repository.NewAuditRepository(database)
	return service.NewAuditService(auditRepo), database, marker, actorID
}

func TestAuditService_RecordAndList(t *testing.T) {
	auditService, _, marker, actorID := setupAuditService(t)

	auditService.Record(service.RecordAuditInput{
		ActorUserID: actorID,
		ActorEmail:  "actor@example.com",
		Action:      model.AuditActionStrategySave,
		TargetType:  "strategy",
		TargetID:    1,
		Detail:      "全局加固策略已更新",
		IP:          marker,
		Success:     true,
	})

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionStrategySave),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 || len(logs) != 1 {
		t.Fatalf("got len=%d total=%d, want 1/1", len(logs), total)
	}
	if logs[0].IP != marker || !logs[0].Success || logs[0].Detail != "全局加固策略已更新" {
		t.Fatalf("unexpected audit log: %+v", logs[0])
	}
}

func TestAuditService_ListNoMatches(t *testing.T) {
	auditService, _, _, actorID := setupAuditService(t)

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(logs) != 0 || total != 0 {
		t.Fatalf("got len=%d total=%d, want empty result", len(logs), total)
	}
}

func TestAuditService_RecordDoesNotPanicWhenRepositoryMissing(t *testing.T) {
	auditService := service.NewAuditService(nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Record() panicked with nil repository: %v", r)
		}
	}()

	auditService.Record(service.RecordAuditInput{
		Action:  model.AuditActionLoginFailure,
		Success: false,
	})
}

func TestAuditService_RecordSwallowsRepositoryCreateError(t *testing.T) {
	auditService, database, marker, actorID := setupAuditService(t)
	callbackName := fmt.Sprintf("audit-service-create-error-%d", time.Now().UnixNano())
	injectedErr := errors.New("injected audit create failure")

	if err := database.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Schema != nil && tx.Statement.Schema.Table == "audit_logs" {
			tx.AddError(injectedErr)
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Callback().Create().Remove(callbackName); err != nil {
			t.Fatalf("remove callback: %v", err)
		}
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Record() panicked on repository error: %v", r)
		}
	}()

	auditService.Record(service.RecordAuditInput{
		ActorUserID: actorID,
		Action:      model.AuditActionAppUpload,
		TargetType:  "app",
		TargetID:    1,
		Detail:      "injected failure",
		IP:          marker,
		Success:     true,
	})

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionAppUpload),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("List() after failed Record() error = %v", err)
	}
	if total != 0 || len(logs) != 0 {
		t.Fatalf("failed audit write should not persist rows, got len=%d total=%d", len(logs), total)
	}
}
