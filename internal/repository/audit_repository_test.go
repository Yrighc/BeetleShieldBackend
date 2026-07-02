package repository

import (
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
)

func setupAuditRepo(t *testing.T) (*AuditRepository, *gorm.DB, string, uint) {
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
	marker := fmt.Sprintf("audit-repo-%d", time.Now().UnixNano())
	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 100_000)
	t.Cleanup(func() {
		database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
	})
	return NewAuditRepository(database), database, marker, actorID
}

func createAuditLog(t *testing.T, repo *AuditRepository, marker string, actorID uint, action model.AuditAction, targetType string, success bool, createdAt time.Time) model.AuditLog {
	t.Helper()
	entry := model.AuditLog{
		ActorUserID: actorID,
		ActorEmail:  "actor@example.com",
		Action:      action,
		TargetType:  targetType,
		TargetID:    42,
		Detail:      marker,
		IP:          marker,
		Success:     success,
		CreatedAt:   createdAt,
	}
	if err := repo.Record(&entry); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	return entry
}

func TestAuditRepository_RecordAndListFilters(t *testing.T) {
	repo, _, marker, actorID := setupAuditRepo(t)
	now := time.Now().UTC()
	createAuditLog(t, repo, marker, actorID, model.AuditActionLoginSuccess, "", true, now.Add(-2*time.Hour))
	appLog := createAuditLog(t, repo, marker, actorID, model.AuditActionAppUpload, "app", true, now.Add(-time.Hour))
	createAuditLog(t, repo, marker, actorID, model.AuditActionLoginFailure, "", false, now)

	tests := []struct {
		name   string
		filter AuditListFilter
		want   int64
	}{
		{name: "action", filter: AuditListFilter{Action: string(model.AuditActionAppUpload)}, want: 1},
		{name: "target type", filter: AuditListFilter{TargetType: "app"}, want: 1},
		{name: "success true", filter: AuditListFilter{Success: boolPtr(true)}, want: 2},
		{name: "success false", filter: AuditListFilter{Success: boolPtr(false)}, want: 1},
		{name: "time range", filter: AuditListFilter{StartTime: timePtr(now.Add(-90 * time.Minute)), EndTime: timePtr(now.Add(-30 * time.Minute))}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.filter.ActorUserID = actorID
			tt.filter.Page = 1
			tt.filter.PageSize = 10
			logs, total, err := repo.List(tt.filter)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			var matched []model.AuditLog
			for _, log := range logs {
				if log.IP == marker {
					matched = append(matched, log)
				}
			}
			if int64(len(matched)) != tt.want {
				t.Fatalf("matched rows = %d, want %d (total=%d)", len(matched), tt.want, total)
			}
		})
	}

	logs, _, err := repo.List(AuditListFilter{ActorUserID: actorID, Action: string(model.AuditActionAppUpload), Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() app upload error = %v", err)
	}
	found := false
	for _, log := range logs {
		if log.ID == appLog.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("recorded app log %d not returned by action filter", appLog.ID)
	}
}

func TestAuditRepository_Pagination(t *testing.T) {
	repo, _, marker, actorID := setupAuditRepo(t)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		createAuditLog(t, repo, marker, actorID, model.AuditActionStrategySave, "strategy", true, now.Add(time.Duration(i)*time.Minute))
	}

	logs, total, err := repo.List(AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionStrategySave),
		Page:        1,
		PageSize:    2,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	matched := 0
	for _, log := range logs {
		if log.IP == marker {
			matched++
		}
	}
	if matched != 2 {
		t.Fatalf("matched page rows = %d, want 2 (total=%d)", matched, total)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func timePtr(v time.Time) *time.Time {
	return &v
}
