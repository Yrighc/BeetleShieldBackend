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

const DefaultStrategyName = "默认加固模板"

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

	if input.Strategy.Emulator {
		args = append(args, "--enable-emulator-detect")
	}
	if input.Strategy.RootDetect {
		args = append(args, "--enable-root-detect")
	}
	if input.Strategy.Signature {
		args = append(args, "--enable-apk-sig-verify", "--apk-sig-policy", "block")
	}
	if input.Strategy.AntiHook || input.Strategy.Frida || input.Strategy.Xposed {
		args = append(args, "--enable-hook-detect")
	}
	if input.Strategy.StringEncrypt {
		args = append(args, "--enable-string-encrypt")
	}
	if input.Strategy.ResEncrypt {
		args = append(args, "--enable-assets-encrypt")
	}
	if input.Strategy.DexLevel == model.DexLevelHigh || input.Strategy.SoShell == model.SoShellVMP {
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
