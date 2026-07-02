package service

import (
	"errors"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

var (
	ErrInvalidDexLevel   = errors.New("invalid dex obfuscation level")
	ErrInvalidSoShell    = errors.New("invalid so shell type")
	ErrInvalidSoStrength = errors.New("so strength must be between 0 and 100")
)

type SaveStrategyInput struct {
	Frida         bool
	Xposed        bool
	Debugger      bool
	Emulator      bool
	DexLevel      model.DexObfuscationLevel
	StringEncrypt bool
	ResMix        bool
	SoShell       model.SoShellType
	SoStrength    int
	TargetSos     []string
	RootDetect    bool
	Signature     bool
	AntiHook      bool
	ResEncrypt    bool
}

var templates = map[string]model.Strategy{
	"finance": {
		Frida: true, Xposed: true, Debugger: true, Emulator: true,
		DexLevel: model.DexLevelHigh, StringEncrypt: true, ResMix: true,
		SoShell: model.SoShellVMP, SoStrength: 90,
		TargetSos:  []string{"libnative-lib.so", "libsec.so"},
		RootDetect: true, Signature: true, AntiHook: true, ResEncrypt: true,
	},
	"game": {
		Frida: true, Xposed: false, Debugger: true, Emulator: false,
		DexLevel: model.DexLevelMedium, StringEncrypt: true, ResMix: false,
		SoShell: model.SoShellAES, SoStrength: 70,
		TargetSos:  []string{"libunity.so", "libmain.so"},
		RootDetect: true, Signature: true, AntiHook: true, ResEncrypt: false,
	},
	"basic": {
		Frida: true, Xposed: false, Debugger: true, Emulator: false,
		DexLevel: model.DexLevelLow, StringEncrypt: false, ResMix: false,
		SoShell: model.SoShellNone, SoStrength: 30,
		TargetSos:  []string{},
		RootDetect: false, Signature: true, AntiHook: false, ResEncrypt: false,
	},
}

var validDexLevels = map[model.DexObfuscationLevel]bool{
	model.DexLevelLow:    true,
	model.DexLevelMedium: true,
	model.DexLevelHigh:   true,
}

var validSoShells = map[model.SoShellType]bool{
	model.SoShellNone:     true,
	model.SoShellAES:      true,
	model.SoShellVMP:      true,
	model.SoShellCustomSo: true,
}

type StrategyService struct {
	strategyRepo *repository.StrategyRepository
}

func NewStrategyService(strategyRepo *repository.StrategyRepository) *StrategyService {
	return &StrategyService{strategyRepo: strategyRepo}
}

func (s *StrategyService) Templates() map[string]model.Strategy {
	return templates
}

func (s *StrategyService) GetCurrent() (*model.Strategy, error) {
	current, err := s.strategyRepo.GetCurrent()
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			defaultStrategy := templates["finance"]
			return &defaultStrategy, nil
		}
		return nil, err
	}
	return current, nil
}

func (s *StrategyService) Save(input SaveStrategyInput, updatedBy uint) (*model.Strategy, error) {
	if !validDexLevels[input.DexLevel] {
		return nil, ErrInvalidDexLevel
	}
	if !validSoShells[input.SoShell] {
		return nil, ErrInvalidSoShell
	}
	if input.SoStrength < 0 || input.SoStrength > 100 {
		return nil, ErrInvalidSoStrength
	}

	strategy := &model.Strategy{
		Frida: input.Frida, Xposed: input.Xposed, Debugger: input.Debugger, Emulator: input.Emulator,
		DexLevel: input.DexLevel, StringEncrypt: input.StringEncrypt, ResMix: input.ResMix,
		SoShell: input.SoShell, SoStrength: input.SoStrength, TargetSos: input.TargetSos,
		RootDetect: input.RootDetect, Signature: input.Signature, AntiHook: input.AntiHook, ResEncrypt: input.ResEncrypt,
		UpdatedBy: updatedBy,
	}
	if err := s.strategyRepo.Save(strategy); err != nil {
		return nil, err
	}
	return strategy, nil
}
