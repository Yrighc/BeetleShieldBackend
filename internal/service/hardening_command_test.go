package service

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"beetleshield-backend/internal/model"
)

func TestNormalizeVMPRules_DefaultAndCustom(t *testing.T) {
	fallback := "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**"
	if got := NormalizeVMPRules("", fallback); got != fallback {
		t.Fatalf("empty rules = %q, want fallback", got)
	}
	custom := "com.example.**\n!com.example.Skip"
	if got := NormalizeVMPRules("  "+custom+"  ", fallback); got != custom {
		t.Fatalf("custom rules = %q, want %q", got, custom)
	}
}

func TestBuildDPTCommand_HighStrengthMapping(t *testing.T) {
	args := BuildDPTCommand(EngineCommandInput{
		JavaBin:    "java",
		JarPath:    "/opt/dpt.jar",
		InputPath:  "/work/input.apk",
		OutputPath: "/work/output.apk",
		RulesPath:  "/work/vmp-rules.txt",
		Strategy: model.Strategy{
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
		},
		EnableFileIntegrityCheck: true,
		EnableProxyDetect:        true,
	})
	want := []string{
		"java", "-jar", "/opt/dpt.jar",
		"-f", "/work/input.apk",
		"-o", "/work/output.apk",
		"--no-sign",
		"--enable-emulator-detect",
		"--enable-root-detect",
		"--enable-apk-sig-verify", "--apk-sig-policy", "block",
		"--enable-hook-detect",
		"--enable-string-encrypt",
		"--enable-assets-encrypt",
		"--enable-vmp", "--vmp-rules", "/work/vmp-rules.txt",
		"--enable-file-integrity-check",
		"--enable-proxy-detect",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v\nwant %#v", args, want)
	}
}

func TestBuildDPTCommand_DeduplicatesHookAndVMP(t *testing.T) {
	args := BuildDPTCommand(EngineCommandInput{
		JavaBin:    "java",
		JarPath:    "/opt/dpt.jar",
		InputPath:  "/work/input.apk",
		OutputPath: "/work/output.apk",
		RulesPath:  "/work/vmp-rules.txt",
		Strategy: model.Strategy{
			Frida:    true,
			Xposed:   true,
			AntiHook: true,
			DexLevel: model.DexLevelHigh,
			SoShell:  model.SoShellVMP,
		},
	})
	if countArg(args, "--enable-hook-detect") != 1 {
		t.Fatalf("hook flag count = %d, want 1 in %#v", countArg(args, "--enable-hook-detect"), args)
	}
	if countArg(args, "--enable-vmp") != 1 {
		t.Fatalf("vmp flag count = %d, want 1 in %#v", countArg(args, "--enable-vmp"), args)
	}
}

func TestSHA256FileAndSignedTestArtifactPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.apk")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	sum, size, err := SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File() error = %v", err)
	}
	if size != 3 {
		t.Fatalf("size = %d, want 3", size)
	}
	if sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256 = %q", sum)
	}
	if got := SignedTestArtifactPath(path); got != filepath.Join(filepath.Dir(path), "output_signed.apk") {
		t.Fatalf("SignedTestArtifactPath() = %q", got)
	}
}

func countArg(args []string, target string) int {
	count := 0
	for _, arg := range args {
		if arg == target {
			count++
		}
	}
	return count
}
