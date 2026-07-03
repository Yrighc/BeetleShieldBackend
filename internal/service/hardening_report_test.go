package service_test

import (
	"testing"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/service"
)

func fullyHardenedStrategy() model.Strategy {
	return model.Strategy{
		Frida:         true,
		Xposed:        true,
		Emulator:      true,
		DexLevel:      model.DexLevelHigh,
		StringEncrypt: true,
		SoShell:       model.SoShellVMP,
		RootDetect:    true,
		Signature:     true,
		AntiHook:      true,
		ResEncrypt:    true,
	}
}

func baseReportTask(strategy model.Strategy) model.HardeningTask {
	return model.HardeningTask{
		ID:                  7,
		TaskNo:              "TASK-20260703-1",
		StrategySnapshot:    strategy,
		UnsignedObjectKey:   "com.example.app/hardening/TASK-1/unsigned.apk",
		UnsignedSHA256:      "unsignedsha",
		SignedTestObjectKey: "com.example.app/hardening/TASK-1/signed_test.apk",
		SignedTestSHA256:    "signedsha",
		App: model.App{
			Name:        "Example App",
			PackageName: "com.example.app",
			Version:     "1.0.0",
		},
	}
}

func TestBuildHardeningReport_FullyHardenedScoresLowRisk(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(fullyHardenedStrategy()), "BeetleShield Engine v2.4.1")

	if report.BeforeScore != 100 {
		t.Fatalf("BeforeScore = %d, want 100", report.BeforeScore)
	}
	if report.AfterScore != 5 {
		t.Fatalf("AfterScore = %d, want 5 (fully hardened = weights sum to 100, clamped at floor 5)", report.AfterScore)
	}
	if report.RiskLevel != model.RiskLevelLow {
		t.Fatalf("RiskLevel = %q, want %q", report.RiskLevel, model.RiskLevelLow)
	}
}

func TestBuildHardeningReport_NoStrategyScoresMaxRiskAndCritical(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{}), "BeetleShield Engine v2.4.1")

	if report.BeforeScore != 100 {
		t.Fatalf("BeforeScore = %d, want 100", report.BeforeScore)
	}
	if report.AfterScore != 100 {
		t.Fatalf("AfterScore = %d, want 100 (nothing enabled)", report.AfterScore)
	}
	if report.RiskLevel != model.RiskLevelCritical {
		t.Fatalf("RiskLevel = %q, want %q", report.RiskLevel, model.RiskLevelCritical)
	}
}

func TestBuildHardeningReport_DebuggerFieldAloneDoesNotReduceRisk(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{Debugger: true}), "v1")
	if report.AfterScore != 100 {
		t.Fatalf("AfterScore = %d, want 100: Strategy.Debugger is not wired to any dpt.jar flag and must not affect scoring", report.AfterScore)
	}
}

func TestBuildHardeningReport_FiveDimensionsWithMergedAntiDebug(t *testing.T) {
	strategy := model.Strategy{
		Emulator: true, // anti-debug/env sub-score: 15/15
		AntiHook: true, // hook sub-score: 15/15 -> merged dimension = 30/30 = 100%
	}
	report := service.BuildHardeningReport(baseReportTask(strategy), "v1")

	if len(report.Dimensions) != 5 {
		t.Fatalf("len(Dimensions) = %d, want 5", len(report.Dimensions))
	}
	dims := map[string]service.ReportDimension{}
	for _, d := range report.Dimensions {
		dims[d.Name] = d
	}
	antiDebug, ok := dims["反调试保护"]
	if !ok {
		t.Fatalf("missing dimension 反调试保护, got %+v", report.Dimensions)
	}
	if antiDebug.Before != 0 || antiDebug.After != 100 {
		t.Fatalf("反调试保护 = %+v, want before=0 after=100", antiDebug)
	}
	dex, ok := dims["DEX 混淆"]
	if !ok || dex.After != 0 {
		t.Fatalf("DEX 混淆 = %+v (ok=%v), want after=0 (DexLevel unset)", dex, ok)
	}
}

func TestBuildHardeningReport_ChecklistHasSixItemsWithKnownStatuses(t *testing.T) {
	strategy := model.Strategy{
		Frida:      true,
		Emulator:   true,
		DexLevel:   model.DexLevelHigh,
		RootDetect: true,
	}
	report := service.BuildHardeningReport(baseReportTask(strategy), "v1")

	if len(report.Checklist) != 6 {
		t.Fatalf("len(Checklist) = %d, want 6", len(report.Checklist))
	}
	byName := map[string]service.ReportChecklistItem{}
	for _, item := range report.Checklist {
		byName[item.Name] = item
	}
	if got := byName["Frida/Xposed 注入防御"].Status; got != "已修复" {
		t.Fatalf("Frida/Xposed 注入防御 status = %q, want 已修复", got)
	}
	if got := byName["硬编码明文字符串泄露"].Status; got != "已保留" {
		t.Fatalf("硬编码明文字符串泄露 status = %q, want 已保留 (StringEncrypt not set)", got)
	}
	if got := byName["SSL Pinning 证书校验"].Status; got != "已保留" {
		t.Fatalf("SSL Pinning 证书校验 status = %q, want 已保留 (always unsupported)", got)
	}
}

func TestBuildHardeningReport_ArtifactPrefersSignedTestOverUnsigned(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{}), "BeetleShield Engine v2.4.1")

	if report.Artifact.FileName != "signed_test.apk" {
		t.Fatalf("Artifact.FileName = %q, want signed_test.apk", report.Artifact.FileName)
	}
	if report.Artifact.SHA256 != "signedsha" {
		t.Fatalf("Artifact.SHA256 = %q, want signedsha", report.Artifact.SHA256)
	}
	if report.Artifact.EngineVersion != "BeetleShield Engine v2.4.1" {
		t.Fatalf("Artifact.EngineVersion = %q", report.Artifact.EngineVersion)
	}
}

func TestBuildHardeningReport_ArtifactFallsBackToUnsignedWhenNoSignedTest(t *testing.T) {
	task := baseReportTask(model.Strategy{})
	task.SignedTestObjectKey = ""
	task.SignedTestSHA256 = ""
	report := service.BuildHardeningReport(task, "v1")

	if report.Artifact.FileName != "unsigned.apk" {
		t.Fatalf("Artifact.FileName = %q, want unsigned.apk", report.Artifact.FileName)
	}
	if report.Artifact.SHA256 != "unsignedsha" {
		t.Fatalf("Artifact.SHA256 = %q, want unsignedsha", report.Artifact.SHA256)
	}
}

func TestBuildHardeningReport_CopiesAppAndTaskIdentity(t *testing.T) {
	report := service.BuildHardeningReport(baseReportTask(model.Strategy{}), "v1")

	if report.TaskID != 7 || report.TaskNo != "TASK-20260703-1" {
		t.Fatalf("identity = %+v", report)
	}
	if report.AppName != "Example App" || report.PackageName != "com.example.app" || report.Version != "1.0.0" {
		t.Fatalf("app identity = %+v", report)
	}
}
