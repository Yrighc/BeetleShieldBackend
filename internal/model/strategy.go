package model

import "time"

type SoShellType string

const (
	SoShellNone SoShellType = "none"
	SoShellVMP  SoShellType = "vmp"
)

type DexObfuscationLevel string

const (
	DexLevelLow    DexObfuscationLevel = "low"
	DexLevelMedium DexObfuscationLevel = "medium"
	DexLevelHigh   DexObfuscationLevel = "high"
)

// SigPolicy mirrors dpt.jar's --apk-sig-policy values. warn only logs a
// signature mismatch; block force-exits the app. Re-signing the hardened
// artifact for local testing (see SignedTestArtifactPath) changes the
// signing cert, so a block policy makes the freshly re-signed test build
// refuse to launch — warn is what dpt.jar itself defaults to for this
// reason.
type SigPolicy string

const (
	SigPolicyWarn  SigPolicy = "warn"
	SigPolicyBlock SigPolicy = "block"
)

type Strategy struct {
	ID                 uint                `gorm:"primaryKey" json:"id"`
	Name               string              `gorm:"size:120;not null;default:'';index" json:"name"`
	Description        string              `gorm:"size:500" json:"description"`
	IsDefault          bool                `gorm:"not null;default:false;index" json:"isDefault"`
	Frida              bool                `json:"frida"`
	Xposed             bool                `json:"xposed"`
	Emulator           bool                `json:"emulator"`
	DexLevel           DexObfuscationLevel `gorm:"size:20" json:"dexLevel"`
	StringEncrypt      bool                `json:"stringEncrypt"`
	ResMix             bool                `json:"resMix"`
	SoShell            SoShellType         `gorm:"size:20" json:"soShell"`
	SoStrength         int                 `json:"soStrength"`
	TargetSos          []string            `gorm:"serializer:json" json:"targetSos"`
	RootDetect         bool                `json:"rootDetect"`
	Signature          bool                `json:"signature"`
	SigPolicy          SigPolicy           `gorm:"size:20" json:"sigPolicy"`
	AntiHook           bool                `json:"antiHook"`
	ResEncrypt         bool                `json:"resEncrypt"`
	ScreenshotProtect  bool                `json:"screenshotProtect"`
	FileIntegrityCheck bool                `json:"fileIntegrityCheck"`
	ProxyDetect        bool                `json:"proxyDetect"`
	VMPRulesText       string              `gorm:"type:text" json:"vmpRulesText"`
	CreatedBy          uint                `json:"createdBy"`
	UpdatedBy          uint                `json:"updatedBy"`
	CreatedAt          time.Time           `json:"createdAt"`
	UpdatedAt          time.Time           `json:"updatedAt"`
}

func (Strategy) TableName() string {
	return "strategies"
}
