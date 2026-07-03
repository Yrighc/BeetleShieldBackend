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
// turns on. dpt.jar's anti-debug (ptrace) protection is always compiled in
// and has no command-line toggle, and its only real SO-shielding mode is
// VMP, so Strategy no longer exposes a "debugger" switch or aes/custom_so
// SoShell values that would silently imply protection the engine can't
// actually provide.
type EffectiveFlags struct {
	EmulatorDetect     bool
	RootDetect         bool
	HookDetect         bool
	SigVerify          bool
	SigPolicy          model.SigPolicy
	StringEncrypt      bool
	AssetsEncrypt      bool
	VMPEnabled         bool
	ScreenshotProtect  bool
	FileIntegrityCheck bool
	ProxyDetect        bool
}

type EngineCommandInput struct {
	JavaBin    string
	JarPath    string
	InputPath  string
	OutputPath string
	RulesPath  string
	Strategy   model.Strategy
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
	flags := EffectiveFlags{
		EmulatorDetect:     s.Emulator,
		RootDetect:         s.RootDetect,
		HookDetect:         s.AntiHook || s.Frida || s.Xposed,
		SigVerify:          s.Signature,
		StringEncrypt:      s.StringEncrypt,
		AssetsEncrypt:      s.ResEncrypt,
		VMPEnabled:         s.DexLevel == model.DexLevelHigh || s.SoShell == model.SoShellVMP,
		ScreenshotProtect:  s.ScreenshotProtect,
		FileIntegrityCheck: s.FileIntegrityCheck,
		ProxyDetect:        s.ProxyDetect,
	}
	if flags.SigVerify {
		flags.SigPolicy = resolveSigPolicy(s.SigPolicy)
	}
	return flags
}

// resolveSigPolicy defaults anything other than an explicit "warn" to
// "block", so Strategy rows saved before SigPolicy existed keep behaving
// exactly like the previously hardcoded "block" policy.
func resolveSigPolicy(p model.SigPolicy) model.SigPolicy {
	if p == model.SigPolicyWarn {
		return model.SigPolicyWarn
	}
	return model.SigPolicyBlock
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
		args = append(args, "--enable-apk-sig-verify", "--apk-sig-policy", string(flags.SigPolicy))
	}
	if flags.ScreenshotProtect {
		args = append(args, "--enable-screenshot-protect")
	}
	if flags.FileIntegrityCheck {
		args = append(args, "--enable-file-integrity-check")
	}
	if flags.HookDetect {
		args = append(args, "--enable-hook-detect")
	}
	if flags.ProxyDetect {
		args = append(args, "--enable-proxy-detect")
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
