package service

import (
	"errors"
	"strings"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

var (
	ErrInvalidDexLevel       = errors.New("invalid dex obfuscation level")
	ErrInvalidSoShell        = errors.New("invalid so shell type")
	ErrInvalidSoStrength     = errors.New("so strength must be between 0 and 100")
	ErrStrategyNotFound      = errors.New("strategy not found")
	ErrStrategyNameRequired  = errors.New("strategy name is required")
	ErrStrategyNameExists    = errors.New("strategy name already exists")
	ErrDefaultStrategyDelete = errors.New("default strategy cannot be deleted")
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

type StrategyPayloadInput struct {
	Name        string
	Description string
	SaveStrategyInput
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
	auditService *AuditService
}

func NewStrategyService(strategyRepo *repository.StrategyRepository, auditService *AuditService) *StrategyService {
	return &StrategyService{strategyRepo: strategyRepo, auditService: auditService}
}

func (s *StrategyService) Templates() map[string]model.Strategy {
	return templates
}

func (s *StrategyService) GetCurrent() (*model.Strategy, error) {
	current, err := s.strategyRepo.GetCurrent()
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			promoted, promoteErr := s.strategyRepo.PromoteLegacyCurrent()
			if promoteErr == nil {
				return promoted, nil
			}
			if errors.Is(promoteErr, gorm.ErrRecordNotFound) {
				defaultStrategy := templates["finance"]
				defaultStrategy.Name = DefaultStrategyName
				defaultStrategy.IsDefault = true
				return &defaultStrategy, nil
			}
			return nil, promoteErr
		}
		return nil, err
	}
	return current, nil
}

func (s *StrategyService) Save(input SaveStrategyInput, updatedBy uint, ip string) (strategy *model.Strategy, err error) {
	return s.SaveCurrent(input, updatedBy, ip)
}

func (s *StrategyService) SaveCurrent(input SaveStrategyInput, updatedBy uint, ip string) (strategy *model.Strategy, err error) {
	defer func() {
		targetID := uint(0)
		if strategy != nil {
			targetID = strategy.ID
		}
		detail := "全局加固策略已更新"
		if err != nil {
			detail = "策略保存失败 - " + err.Error()
		}
		s.auditService.Record(RecordAuditInput{
			ActorUserID: updatedBy,
			Action:      model.AuditActionStrategySave,
			TargetType:  "strategy",
			TargetID:    targetID,
			Detail:      detail,
			IP:          ip,
			Success:     err == nil,
		})
	}()

	if !validDexLevels[input.DexLevel] {
		return nil, ErrInvalidDexLevel
	}
	if !validSoShells[input.SoShell] {
		return nil, ErrInvalidSoShell
	}
	if input.SoStrength < 0 || input.SoStrength > 100 {
		return nil, ErrInvalidSoStrength
	}

	strategy = &model.Strategy{
		Name: DefaultStrategyName, IsDefault: true,
		Frida: input.Frida, Xposed: input.Xposed, Debugger: input.Debugger, Emulator: input.Emulator,
		DexLevel: input.DexLevel, StringEncrypt: input.StringEncrypt, ResMix: input.ResMix,
		SoShell: input.SoShell, SoStrength: input.SoStrength, TargetSos: input.TargetSos,
		RootDetect: input.RootDetect, Signature: input.Signature, AntiHook: input.AntiHook, ResEncrypt: input.ResEncrypt,
		CreatedBy: updatedBy, UpdatedBy: updatedBy,
	}
	if err := s.strategyRepo.SaveCurrent(strategy); err != nil {
		return nil, err
	}
	return strategy, nil
}

func (s *StrategyService) List(filter repository.StrategyListFilter) ([]model.Strategy, int64, error) {
	return s.strategyRepo.List(filter)
}

func (s *StrategyService) Get(id uint) (*model.Strategy, error) {
	strategy, err := s.strategyRepo.FindRegularByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrStrategyNotFound
		}
		return nil, err
	}
	return strategy, nil
}

func (s *StrategyService) Create(input StrategyPayloadInput, createdBy uint, ip string) (strategy *model.Strategy, err error) {
	defer s.recordStrategyMutationAudit(createdBy, ip, "创建策略：", &strategy, &err)

	if err := s.validateStrategyPayload(input, 0); err != nil {
		return nil, err
	}

	strategy = &model.Strategy{
		Name: strings.TrimSpace(input.Name), Description: strings.TrimSpace(input.Description),
		Frida: input.Frida, Xposed: input.Xposed, Debugger: input.Debugger, Emulator: input.Emulator,
		DexLevel: input.DexLevel, StringEncrypt: input.StringEncrypt, ResMix: input.ResMix,
		SoShell: input.SoShell, SoStrength: input.SoStrength, TargetSos: input.TargetSos,
		RootDetect: input.RootDetect, Signature: input.Signature, AntiHook: input.AntiHook, ResEncrypt: input.ResEncrypt,
		CreatedBy: createdBy, UpdatedBy: createdBy,
	}
	if err := s.strategyRepo.Create(strategy); err != nil {
		return nil, err
	}
	return strategy, nil
}

func (s *StrategyService) Update(id uint, input StrategyPayloadInput, updatedBy uint, ip string) (strategy *model.Strategy, err error) {
	defer s.recordStrategyMutationAudit(updatedBy, ip, "更新策略：", &strategy, &err)

	existing, err := s.strategyRepo.FindRegularByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrStrategyNotFound
		}
		return nil, err
	}
	if err := s.validateStrategyPayload(input, id); err != nil {
		return nil, err
	}

	existing.Name = strings.TrimSpace(input.Name)
	existing.Description = strings.TrimSpace(input.Description)
	existing.Frida = input.Frida
	existing.Xposed = input.Xposed
	existing.Debugger = input.Debugger
	existing.Emulator = input.Emulator
	existing.DexLevel = input.DexLevel
	existing.StringEncrypt = input.StringEncrypt
	existing.ResMix = input.ResMix
	existing.SoShell = input.SoShell
	existing.SoStrength = input.SoStrength
	existing.TargetSos = input.TargetSos
	existing.RootDetect = input.RootDetect
	existing.Signature = input.Signature
	existing.AntiHook = input.AntiHook
	existing.ResEncrypt = input.ResEncrypt
	existing.UpdatedBy = updatedBy
	if err := s.strategyRepo.Update(existing); err != nil {
		return nil, err
	}
	return existing, nil
}

func (s *StrategyService) Delete(id uint, actorID uint, ip string) (err error) {
	var strategy *model.Strategy
	defer s.recordStrategyMutationAudit(actorID, ip, "删除策略：", &strategy, &err)

	found, err := s.strategyRepo.FindByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrStrategyNotFound
		}
		return err
	}
	strategy = found
	if found.IsDefault {
		return ErrDefaultStrategyDelete
	}
	return s.strategyRepo.Delete(id)
}

func (s *StrategyService) ResolveForHardening(strategyID uint) (*model.Strategy, string, error) {
	if strategyID == 0 {
		strategy, err := s.GetCurrent()
		if err != nil {
			return nil, "", err
		}
		return strategy, DefaultStrategyName, nil
	}

	strategy, err := s.strategyRepo.FindByID(strategyID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrStrategyNotFound
		}
		return nil, "", err
	}
	name := strategy.Name
	if strategy.IsDefault || name == "" {
		name = DefaultStrategyName
	}
	return strategy, name, nil
}

func (s *StrategyService) validateStrategyPayload(input StrategyPayloadInput, excludeID uint) error {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return ErrStrategyNameRequired
	}
	if err := validateStrategyFields(input.SaveStrategyInput); err != nil {
		return err
	}
	exists, err := s.strategyRepo.NameExists(name, excludeID)
	if err != nil {
		return err
	}
	if exists {
		return ErrStrategyNameExists
	}
	return nil
}

func validateStrategyFields(input SaveStrategyInput) error {
	if !validDexLevels[input.DexLevel] {
		return ErrInvalidDexLevel
	}
	if !validSoShells[input.SoShell] {
		return ErrInvalidSoShell
	}
	if input.SoStrength < 0 || input.SoStrength > 100 {
		return ErrInvalidSoStrength
	}
	return nil
}

func (s *StrategyService) recordStrategyMutationAudit(actorID uint, ip string, successPrefix string, strategy **model.Strategy, opErr *error) {
	targetID := uint(0)
	name := ""
	if strategy != nil && *strategy != nil {
		targetID = (*strategy).ID
		name = (*strategy).Name
	}
	detail := successPrefix + name
	if opErr != nil && *opErr != nil {
		detail = "策略保存失败 - " + (*opErr).Error()
	}
	s.auditService.Record(RecordAuditInput{
		ActorUserID: actorID,
		Action:      model.AuditActionStrategySave,
		TargetType:  "strategy",
		TargetID:    targetID,
		Detail:      detail,
		IP:          ip,
		Success:     opErr == nil || *opErr == nil,
	})
}
