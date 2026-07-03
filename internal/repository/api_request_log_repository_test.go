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

func setupAPIRequestLogRepo(t *testing.T) (*APIRequestLogRepository, *gorm.DB, string, uint) {
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
	marker := fmt.Sprintf("/api-request-log-repo-%d", time.Now().UnixNano())
	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 100_000)
	t.Cleanup(func() {
		database.Unscoped().Where("path = ?", marker).Delete(&model.APIRequestLog{})
	})
	return NewAPIRequestLogRepository(database), database, marker, actorID
}

func createAPIRequestLog(t *testing.T, repo *APIRequestLogRepository, marker string, actorID uint, method string, status int, createdAt time.Time) model.APIRequestLog {
	t.Helper()
	entry := model.APIRequestLog{
		Method:      method,
		Path:        marker,
		Status:      status,
		LatencyMS:   42,
		ClientIP:    "127.0.0.1",
		ActorUserID: actorID,
		CreatedAt:   createdAt,
	}
	if err := repo.Record(&entry); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	return entry
}

func TestAPIRequestLogRepository_RecordAndListFilters(t *testing.T) {
	repo, _, marker, actorID := setupAPIRequestLogRepo(t)
	now := time.Now().UTC()
	createAPIRequestLog(t, repo, marker, actorID, "GET", 200, now.Add(-2*time.Hour))
	postLog := createAPIRequestLog(t, repo, marker, actorID, "POST", 201, now.Add(-time.Hour))
	createAPIRequestLog(t, repo, marker, actorID, "GET", 500, now)

	tests := []struct {
		name   string
		filter APIRequestLogListFilter
		want   int64
	}{
		{name: "method", filter: APIRequestLogListFilter{Method: "POST"}, want: 1},
		{name: "path", filter: APIRequestLogListFilter{Path: marker}, want: 3},
		{name: "status", filter: APIRequestLogListFilter{Status: intPtr(500)}, want: 1},
		{name: "actor user id", filter: APIRequestLogListFilter{ActorUserID: actorID}, want: 3},
		{name: "time range", filter: APIRequestLogListFilter{StartTime: timePtrAPI(now.Add(-90 * time.Minute)), EndTime: timePtrAPI(now.Add(-30 * time.Minute))}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.filter.Path = joinPathFilter(tt.filter.Path, marker)
			tt.filter.Page = 1
			tt.filter.PageSize = 10
			logs, total, err := repo.List(tt.filter)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			var matched []model.APIRequestLog
			for _, log := range logs {
				if log.Path == marker {
					matched = append(matched, log)
				}
			}
			if int64(len(matched)) != tt.want {
				t.Fatalf("matched rows = %d, want %d (total=%d)", len(matched), tt.want, total)
			}
		})
	}

	logs, _, err := repo.List(APIRequestLogListFilter{Path: marker, Method: "POST", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() post log error = %v", err)
	}
	found := false
	for _, log := range logs {
		if log.ID == postLog.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("recorded post log %d not returned by method filter", postLog.ID)
	}
}

func TestAPIRequestLogRepository_Pagination(t *testing.T) {
	repo, _, marker, actorID := setupAPIRequestLogRepo(t)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		createAPIRequestLog(t, repo, marker, actorID, "GET", 200, now.Add(time.Duration(i)*time.Minute))
	}

	logs, total, err := repo.List(APIRequestLogListFilter{
		Path:     marker,
		Page:     1,
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	matched := 0
	for _, log := range logs {
		if log.Path == marker {
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

// joinPathFilter ensures every sub-test scopes its query to this test run's
// unique marker path, in addition to whatever filter field it's exercising,
// since api_request_logs has no natural per-test scoping column and the DB
// is shared across concurrent test runs.
func joinPathFilter(filterPath, marker string) string {
	if filterPath != "" && filterPath != marker {
		return filterPath
	}
	return marker
}

func intPtr(v int) *int {
	return &v
}

func timePtrAPI(v time.Time) *time.Time {
	return &v
}
