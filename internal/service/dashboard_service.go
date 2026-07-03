package service

import (
	"fmt"
	"math"
	"time"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type HourlyPoint struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

type ResultDistribution struct {
	Success    int `json:"success"`
	Failed     int `json:"failed"`
	Processing int `json:"processing"`
}

type DashboardTaskItem struct {
	TaskID          uint                      `json:"taskId"`
	TaskNo          string                    `json:"taskNo"`
	AppName         string                    `json:"appName"`
	PackageName     string                    `json:"packageName"`
	Version         string                    `json:"version"`
	Status          model.HardeningTaskStatus `json:"status"`
	DurationSeconds *int                      `json:"durationSeconds"`
	CreatedAt       time.Time                 `json:"createdAt"`
}

type DashboardRiskApp struct {
	AppID        uint            `json:"appId"`
	Name         string          `json:"name"`
	PackageName  string          `json:"packageName"`
	RiskLevel    model.RiskLevel `json:"riskLevel"`
	DisplayScore int             `json:"displayScore"`
}

type DashboardSystemStatus struct {
	EngineVersion string `json:"engineVersion"`
	QueueCount    int    `json:"queueCount"`
}

type DashboardOverview struct {
	TodayTaskCount     int                   `json:"todayTaskCount"`
	SuccessRate        float64               `json:"successRate"`
	AvgDurationSeconds int                   `json:"avgDurationSeconds"`
	QueueCount         int                   `json:"queueCount"`
	HourlyTrend        []HourlyPoint         `json:"hourlyTrend"`
	ResultDistribution ResultDistribution    `json:"resultDistribution"`
	RecentTasks        []DashboardTaskItem   `json:"recentTasks"`
	RiskTop5           []DashboardRiskApp    `json:"riskTop5"`
	SystemStatus       DashboardSystemStatus `json:"systemStatus"`
}

// riskLevelDisplayScore maps the 4-level RiskLevel enum to a fixed display
// score for the Top5 progress bars. This is not a precise numeric score
// (App never stores one) — it only needs to render in the right relative
// order and magnitude.
var riskLevelDisplayScore = map[model.RiskLevel]int{
	model.RiskLevelCritical: 90,
	model.RiskLevelHigh:     65,
	model.RiskLevelMedium:   40,
	model.RiskLevelLow:      15,
}

type DashboardService struct {
	hardeningRepo *repository.HardeningRepository
	appRepo       *repository.AppRepository
	engineVersion string
}

func NewDashboardService(hardeningRepo *repository.HardeningRepository, appRepo *repository.AppRepository, engineVersion string) *DashboardService {
	return &DashboardService{
		hardeningRepo: hardeningRepo,
		appRepo:       appRepo,
		engineVersion: engineVersion,
	}
}

// GetOverview is a read-only aggregation: it never writes to the database,
// and "today" is always the caller's local calendar day at the moment of
// the call.
func (s *DashboardService) GetOverview() (*DashboardOverview, error) {
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	statusCounts, err := s.hardeningRepo.CountByStatusSince(startOfDay)
	if err != nil {
		return nil, err
	}
	hourly, err := s.hardeningRepo.HourlyCountsSince(startOfDay)
	if err != nil {
		return nil, err
	}
	avgSeconds, hasAvg, err := s.hardeningRepo.AverageCompletedDurationSince(startOfDay)
	if err != nil {
		return nil, err
	}
	queueCount, err := s.hardeningRepo.QueueCount()
	if err != nil {
		return nil, err
	}
	recentTasks, err := s.hardeningRepo.Recent(7)
	if err != nil {
		return nil, err
	}
	riskApps, err := s.appRepo.TopByRiskLevel(5)
	if err != nil {
		return nil, err
	}

	completed := int(statusCounts[model.HardeningTaskStatusCompleted])
	failed := int(statusCounts[model.HardeningTaskStatusFailed])
	queued := int(statusCounts[model.HardeningTaskStatusQueued])
	running := int(statusCounts[model.HardeningTaskStatusRunning])

	var successRate float64
	if completed+failed > 0 {
		successRate = float64(completed) / float64(completed+failed) * 100
	}

	avgDuration := 0
	if hasAvg {
		avgDuration = int(math.Round(avgSeconds))
	}

	hourlyTrend := make([]HourlyPoint, 24)
	for h := 0; h < 24; h++ {
		hourlyTrend[h] = HourlyPoint{Hour: fmt.Sprintf("%02d:00", h), Count: int(hourly[h])}
	}

	taskItems := make([]DashboardTaskItem, 0, len(recentTasks))
	for _, task := range recentTasks {
		item := DashboardTaskItem{
			TaskID:      task.ID,
			TaskNo:      task.TaskNo,
			AppName:     task.App.Name,
			PackageName: task.App.PackageName,
			Version:     task.App.Version,
			Status:      task.Status,
			CreatedAt:   task.CreatedAt,
		}
		if task.StartedAt != nil && task.FinishedAt != nil {
			seconds := int(task.FinishedAt.Sub(*task.StartedAt).Seconds())
			item.DurationSeconds = &seconds
		}
		taskItems = append(taskItems, item)
	}

	riskItems := make([]DashboardRiskApp, 0, len(riskApps))
	for _, app := range riskApps {
		if app.RiskLevel == nil {
			continue
		}
		riskItems = append(riskItems, DashboardRiskApp{
			AppID:        app.ID,
			Name:         app.Name,
			PackageName:  app.PackageName,
			RiskLevel:    *app.RiskLevel,
			DisplayScore: riskLevelDisplayScore[*app.RiskLevel],
		})
	}

	return &DashboardOverview{
		TodayTaskCount:     completed + failed + queued + running,
		SuccessRate:        successRate,
		AvgDurationSeconds: avgDuration,
		QueueCount:         int(queueCount),
		HourlyTrend:        hourlyTrend,
		ResultDistribution: ResultDistribution{
			Success:    completed,
			Failed:     failed,
			Processing: queued + running,
		},
		RecentTasks: taskItems,
		RiskTop5:    riskItems,
		SystemStatus: DashboardSystemStatus{
			EngineVersion: s.engineVersion,
			QueueCount:    int(queueCount),
		},
	}, nil
}
