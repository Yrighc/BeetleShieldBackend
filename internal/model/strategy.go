package model

import "time"

type SoShellType string

const (
	SoShellNone     SoShellType = "none"
	SoShellAES      SoShellType = "aes"
	SoShellVMP      SoShellType = "vmp"
	SoShellCustomSo SoShellType = "custom_so"
)

type DexObfuscationLevel string

const (
	DexLevelLow    DexObfuscationLevel = "low"
	DexLevelMedium DexObfuscationLevel = "medium"
	DexLevelHigh   DexObfuscationLevel = "high"
)

type Strategy struct {
	ID            uint                `gorm:"primaryKey" json:"id"`
	Frida         bool                `json:"frida"`
	Xposed        bool                `json:"xposed"`
	Debugger      bool                `json:"debugger"`
	Emulator      bool                `json:"emulator"`
	DexLevel      DexObfuscationLevel `gorm:"size:20" json:"dexLevel"`
	StringEncrypt bool                `json:"stringEncrypt"`
	ResMix        bool                `json:"resMix"`
	SoShell       SoShellType         `gorm:"size:20" json:"soShell"`
	SoStrength    int                 `json:"soStrength"`
	TargetSos     []string            `gorm:"serializer:json" json:"targetSos"`
	RootDetect    bool                `json:"rootDetect"`
	Signature     bool                `json:"signature"`
	AntiHook      bool                `json:"antiHook"`
	ResEncrypt    bool                `json:"resEncrypt"`
	UpdatedBy     uint                `json:"updatedBy"`
	CreatedAt     time.Time           `json:"createdAt"`
	UpdatedAt     time.Time           `json:"updatedAt"`
}

func (Strategy) TableName() string {
	return "strategies"
}
