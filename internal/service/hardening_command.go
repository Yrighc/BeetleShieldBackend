package service

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"beetleshield-backend/internal/model"
)

const DefaultStrategyName = "默认加固策略"

// EffectiveFlags captures which dpt.jar engine flags a Strategy actually
// turns on. This is deliberately narrower than the Strategy struct itself:
// Strategy.Debugger and SoShell values "aes"/"custom_so" are stored and
// editable in Strategy Center but were never wired to a real dpt.jar
// parameter, so they must not silently imply protection anywhere that reads
// this struct (BuildDPTCommand today, the hardening report scorer next).
type EffectiveFlags struct {
	EmulatorDetect bool
	RootDetect     bool
	HookDetect     bool
	SigVerify      bool
	StringEncrypt  bool
	AssetsEncrypt  bool
	VMPEnabled     bool
}

type EngineCommandInput struct {
	JavaBin                  string
	JarPath                  string
	InputPath                string
	OutputPath               string
	RulesPath                string
	Strategy                 model.Strategy
	EnableFileIntegrityCheck bool
	EnableProxyDetect        bool
}

type ArtifactInfo struct {
	Path      string
	ObjectKey string
	Size      int64
	SHA256    string
}

func NormalizeVMPRules(input string, fallback string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func ResolveEffectiveFlags(s model.Strategy) EffectiveFlags {
	return EffectiveFlags{
		EmulatorDetect: s.Emulator,
		RootDetect:     s.RootDetect,
		HookDetect:     s.AntiHook || s.Frida || s.Xposed,
		SigVerify:      s.Signature,
		StringEncrypt:  s.StringEncrypt,
		AssetsEncrypt:  s.ResEncrypt,
		VMPEnabled:     s.DexLevel == model.DexLevelHigh || s.SoShell == model.SoShellVMP,
	}
}

func BuildDPTCommand(input EngineCommandInput) []string {
	javaBin := input.JavaBin
	if javaBin == "" {
		javaBin = "java"
	}

	args := []string{
		javaBin, "-jar", input.JarPath,
		"-f", input.InputPath,
		"-o", input.OutputPath,
		"--no-sign",
	}

	flags := ResolveEffectiveFlags(input.Strategy)

	if flags.EmulatorDetect {
		args = append(args, "--enable-emulator-detect")
	}
	if flags.RootDetect {
		args = append(args, "--enable-root-detect")
	}
	if flags.SigVerify {
		args = append(args, "--enable-apk-sig-verify", "--apk-sig-policy", "block")
	}
	if flags.HookDetect {
		args = append(args, "--enable-hook-detect")
	}
	if flags.StringEncrypt {
		args = append(args, "--enable-string-encrypt")
	}
	if flags.AssetsEncrypt {
		args = append(args, "--enable-assets-encrypt")
	}
	if flags.VMPEnabled {
		args = append(args, "--enable-vmp", "--vmp-rules", input.RulesPath)
	}
	if input.EnableFileIntegrityCheck {
		args = append(args, "--enable-file-integrity-check")
	}
	if input.EnableProxyDetect {
		args = append(args, "--enable-proxy-detect")
	}

	return args
}

func SHA256File(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func SignedTestArtifactPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	if ext == "" {
		return outputPath + "_signed"
	}
	return strings.TrimSuffix(outputPath, ext) + "_signed" + ext
}
