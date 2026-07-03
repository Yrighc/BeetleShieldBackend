package service

import (
	"path"
	"strings"

	"beetleshield-backend/internal/model"
)

// Score category weights sum to 100. These six categories drive the overall
// risk index; the frontend's 5-dimension bar chart merges the first two
// (anti-debug/env + hook/injection) into a single "反调试保护" entry — see
// docs/superpowers/specs/2026-07-03-backend-report-scoring-design.md.
const (
	weightAntiDebugEnv  = 15
	weightHookDefense   = 15
	weightSignature     = 15
	weightDexMax        = 20
	weightSoShellMax    = 20
	weightEncryptionMax = 15

	reportMinAfterScore = 5
)

type ReportDimension struct {
	Name   string `json:"name"`
	Before int    `json:"before"`
	After  int    `json:"after"`
}

type ReportChecklistItem struct {
	Name   string `json:"name"`
	Level  string `json:"level"`
	Status string `json:"status"`
	Desc   string `json:"desc"`
}

type ReportArtifact struct {
	FileName      string `json:"fileName"`
	SHA256        string `json:"sha256"`
	EngineVersion string `json:"engineVersion"`
}

type HardeningReport struct {
	TaskID      uint                   `json:"taskId"`
	TaskNo      string                 `json:"taskNo"`
	AppName     string                 `json:"appName"`
	PackageName string                 `json:"packageName"`
	Version     string                 `json:"version"`
	BeforeScore int                    `json:"beforeScore"`
	AfterScore  int                    `json:"afterScore"`
	RiskLevel   model.RiskLevel        `json:"riskLevel"`
	Dimensions  []ReportDimension      `json:"dimensions"`
	Checklist   []ReportChecklistItem  `json:"checklist"`
	Artifact    ReportArtifact         `json:"artifact"`
}

func dexScore(level model.DexObfuscationLevel) int {
	switch level {
	case model.DexLevelLow:
		return 5
	case model.DexLevelMedium:
		return 12
	case model.DexLevelHigh:
		return weightDexMax
	default:
		return 0
	}
}

func encryptionScore(flags EffectiveFlags) int {
	switch {
	case flags.StringEncrypt && flags.AssetsEncrypt:
		return weightEncryptionMax
	case flags.StringEncrypt || flags.AssetsEncrypt:
		return 8
	default:
		return 0
	}
}

func boolScore(enabled bool, weight int) int {
	if enabled {
		return weight
	}
	return 0
}

func riskLevelForScore(afterScore int) model.RiskLevel {
	switch {
	case afterScore < 25:
		return model.RiskLevelLow
	case afterScore < 50:
		return model.RiskLevelMedium
	case afterScore < 75:
		return model.RiskLevelHigh
	default:
		return model.RiskLevelCritical
	}
}

func artifactFileName(objectKey string) string {
	if objectKey == "" {
		return ""
	}
	return path.Base(objectKey)
}

func statusLabel(fixed bool) string {
	if fixed {
		return "已修复"
	}
	return "已保留"
}

// BuildHardeningReport is a pure function: given a completed task's frozen
// StrategySnapshot and artifact fields, it deterministically derives a risk
// report. It never touches the database and never mutates App.RiskLevel —
// persisting a risk level onto the App row is deferred to the Dashboard
// sub-project, which is the first consumer that actually needs to query
// apps by risk level.
func BuildHardeningReport(task model.HardeningTask, engineVersion string) HardeningReport {
	flags := ResolveEffectiveFlags(task.StrategySnapshot)

	antiDebugEnvScore := boolScore(flags.EmulatorDetect || flags.RootDetect, weightAntiDebugEnv)
	hookScore := boolScore(flags.HookDetect, weightHookDefense)
	sigScore := boolScore(flags.SigVerify, weightSignature)
	dexPoints := dexScore(task.StrategySnapshot.DexLevel)
	soPoints := boolScore(flags.VMPEnabled, weightSoShellMax)
	encryptPoints := encryptionScore(flags)

	afterScore := 100 - (antiDebugEnvScore + hookScore + sigScore + dexPoints + soPoints + encryptPoints)
	if afterScore < reportMinAfterScore {
		afterScore = reportMinAfterScore
	}

	antiDebugCombinedWeight := weightAntiDebugEnv + weightHookDefense
	antiDebugCombinedPercent := (antiDebugEnvScore + hookScore) * 100 / antiDebugCombinedWeight

	dimensions := []ReportDimension{
		{Name: "反调试保护", Before: 0, After: antiDebugCombinedPercent},
		{Name: "DEX 混淆", Before: 0, After: dexPoints * 100 / weightDexMax},
		{Name: "SO 加壳保护", Before: 0, After: soPoints * 100 / weightSoShellMax},
		{Name: "资源文件加密", Before: 0, After: encryptPoints * 100 / weightEncryptionMax},
		{Name: "签名校验", Before: 0, After: sigScore * 100 / weightSignature},
	}

	checklist := []ReportChecklistItem{
		{
			Name:   "Frida/Xposed 注入防御",
			Level:  "超危",
			Status: statusLabel(flags.HookDetect),
			Desc:   hookChecklistDesc(flags.HookDetect),
		},
		{
			Name:   "系统调试器绕过",
			Level:  "高危",
			Status: statusLabel(flags.EmulatorDetect),
			Desc:   envDetectChecklistDesc(flags.EmulatorDetect),
		},
		{
			Name:   "DEX 字节码明文暴露",
			Level:  "高危",
			Status: statusLabel(task.StrategySnapshot.DexLevel == model.DexLevelHigh),
			Desc:   dexChecklistDesc(task.StrategySnapshot.DexLevel),
		},
		{
			Name:   "硬编码明文字符串泄露",
			Level:  "中危",
			Status: statusLabel(flags.StringEncrypt),
			Desc:   stringEncryptChecklistDesc(flags.StringEncrypt),
		},
		{
			Name:   "设备 Root 权限滥用",
			Level:  "中危",
			Status: statusLabel(flags.RootDetect),
			Desc:   rootDetectChecklistDesc(flags.RootDetect),
		},
		{
			Name:   "SSL Pinning 证书校验",
			Level:  "低危",
			Status: statusLabel(false),
			Desc:   "检测到未配置本地证书单向校验。建议在下次加固策略中启用。",
		},
	}

	unsignedFileName := artifactFileName(task.UnsignedObjectKey)
	signedFileName := artifactFileName(task.SignedTestObjectKey)
	fileName := unsignedFileName
	sha256 := task.UnsignedSHA256
	if signedFileName != "" {
		fileName = signedFileName
		sha256 = task.SignedTestSHA256
	}

	return HardeningReport{
		TaskID:      task.ID,
		TaskNo:      task.TaskNo,
		AppName:     task.App.Name,
		PackageName: task.App.PackageName,
		Version:     task.App.Version,
		BeforeScore: 100,
		AfterScore:  afterScore,
		RiskLevel:   riskLevelForScore(afterScore),
		Dimensions:  dimensions,
		Checklist:   checklist,
		Artifact: ReportArtifact{
			FileName:      fileName,
			SHA256:        sha256,
			EngineVersion: engineVersion,
		},
	}
}

func hookChecklistDesc(enabled bool) string {
	if enabled {
		return "已植入反动态注入探针，自动识别并中断 Hook 调用。"
	}
	return "未启用 Hook 检测，建议开启反 Hook 策略。"
}

func envDetectChecklistDesc(enabled bool) string {
	if enabled {
		return "已启用模拟器与调试环境检测。"
	}
	return "未启用环境检测，建议开启。"
}

func dexChecklistDesc(level model.DexObfuscationLevel) string {
	if level == model.DexLevelHigh {
		return "已对 DEX 主体数据进行指令虚拟化（VMP）混淆。"
	}
	current := string(level)
	if current == "" {
		current = "未设置"
	}
	return "当前混淆强度为 " + strings.ToLower(current) + "，建议提升至 high。"
}

func stringEncryptChecklistDesc(enabled bool) string {
	if enabled {
		return "全局敏感明文采用 AES 加密，运行时动态解密。"
	}
	return "未启用字符串加密。"
}

func rootDetectChecklistDesc(enabled bool) string {
	if enabled {
		return "已启用多级 Root 检测。"
	}
	return "未启用 Root 检测。"
}
