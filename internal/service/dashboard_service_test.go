package service_test

import (
	"context"
	"testing"
	"time"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/service"
)

func TestDashboardService_GetOverviewReflectsNewCompletedTaskAndRiskApp(t *testing.T) {
	svc, appRepo, hardeningRepo, _, scope, _ := setupHardeningServiceTestWithAuditAndDB(t)
	dashboardSvc := service.NewDashboardService(hardeningRepo, appRepo, "BeetleShield Engine v2.4.1")

	before, err := dashboardSvc.GetOverview()
	if err != nil {
		t.Fatalf("GetOverview() before error = %v", err)
	}

	app := createHardeningServiceApp(t, appRepo, scope, "overview")
	detail, err := svc.Create(context.Background(), service.CreateHardeningTaskInput{AppID: app.ID, CreatedBy: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	startedAt := time.Now()
	finishedAt := startedAt.Add(125 * time.Second)
	if err := hardeningRepo.MarkTaskRunning(detail.Task.ID, startedAt); err != nil {
		t.Fatalf("MarkTaskRunning() error = %v", err)
	}
	if err := hardeningRepo.CompleteTaskForApp(detail.Task.ID, "unsigned.apk", 10, "abc", "signed.apk", 11, "def", finishedAt, model.RiskLevelCritical); err != nil {
		t.Fatalf("CompleteTaskForApp() error = %v", err)
	}

	after, err := dashboardSvc.GetOverview()
	if err != nil {
		t.Fatalf("GetOverview() after error = %v", err)
	}

	if after.ResultDistribution.Success-before.ResultDistribution.Success != 1 {
		t.Fatalf("ResultDistribution.Success delta = %d, want 1 (before=%+v after=%+v)",
			after.ResultDistribution.Success-before.ResultDistribution.Success, before.ResultDistribution, after.ResultDistribution)
	}
	if after.TodayTaskCount-before.TodayTaskCount != 1 {
		t.Fatalf("TodayTaskCount delta = %d, want 1", after.TodayTaskCount-before.TodayTaskCount)
	}

	if len(after.RecentTasks) == 0 || after.RecentTasks[0].TaskNo != detail.Task.TaskNo {
		t.Fatalf("RecentTasks[0] = %+v, want TaskNo %q first (just-created task must sort first)", after.RecentTasks, detail.Task.TaskNo)
	}
	if after.RecentTasks[0].DurationSeconds == nil || *after.RecentTasks[0].DurationSeconds != 125 {
		t.Fatalf("RecentTasks[0].DurationSeconds = %v, want 125", after.RecentTasks[0].DurationSeconds)
	}

	if len(after.RiskTop5) == 0 || after.RiskTop5[0].PackageName != app.PackageName {
		t.Fatalf("RiskTop5[0] = %+v, want PackageName %q first (critical risk level must rank first)", after.RiskTop5, app.PackageName)
	}
	if after.RiskTop5[0].DisplayScore != 90 {
		t.Fatalf("RiskTop5[0].DisplayScore = %d, want 90 (critical mapping)", after.RiskTop5[0].DisplayScore)
	}

	if after.SystemStatus.EngineVersion != "BeetleShield Engine v2.4.1" {
		t.Fatalf("SystemStatus.EngineVersion = %q", after.SystemStatus.EngineVersion)
	}
	if len(after.HourlyTrend) != 24 {
		t.Fatalf("len(HourlyTrend) = %d, want 24", len(after.HourlyTrend))
	}
}
