package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/service"
)

type StrategyHandler struct {
	strategyService *service.StrategyService
}

func NewStrategyHandler(strategyService *service.StrategyService) *StrategyHandler {
	return &StrategyHandler{strategyService: strategyService}
}

func (h *StrategyHandler) Templates(c *gin.Context) {
	response.Success(c, http.StatusOK, h.strategyService.Templates())
}

func (h *StrategyHandler) GetCurrent(c *gin.Context) {
	current, err := h.strategyService.GetCurrent()
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50009, "查询当前策略失败")
		return
	}
	response.Success(c, http.StatusOK, current)
}

type saveStrategyRequest struct {
	Frida         bool                      `json:"frida"`
	Xposed        bool                      `json:"xposed"`
	Debugger      bool                      `json:"debugger"`
	Emulator      bool                      `json:"emulator"`
	DexLevel      model.DexObfuscationLevel `json:"dexLevel" binding:"required"`
	StringEncrypt bool                      `json:"stringEncrypt"`
	ResMix        bool                      `json:"resMix"`
	SoShell       model.SoShellType         `json:"soShell" binding:"required"`
	SoStrength    int                       `json:"soStrength"`
	TargetSos     []string                  `json:"targetSos"`
	RootDetect    bool                      `json:"rootDetect"`
	Signature     bool                      `json:"signature"`
	AntiHook      bool                      `json:"antiHook"`
	ResEncrypt    bool                      `json:"resEncrypt"`
}

func (h *StrategyHandler) SaveCurrent(c *gin.Context) {
	var req saveStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40011, err.Error())
		return
	}

	userID := c.GetUint(middleware.ContextUserIDKey)

	saved, err := h.strategyService.Save(service.SaveStrategyInput{
		Frida: req.Frida, Xposed: req.Xposed, Debugger: req.Debugger, Emulator: req.Emulator,
		DexLevel: req.DexLevel, StringEncrypt: req.StringEncrypt, ResMix: req.ResMix,
		SoShell: req.SoShell, SoStrength: req.SoStrength, TargetSos: req.TargetSos,
		RootDetect: req.RootDetect, Signature: req.Signature, AntiHook: req.AntiHook, ResEncrypt: req.ResEncrypt,
	}, userID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidDexLevel):
			response.Error(c, http.StatusBadRequest, 40012, err.Error())
		case errors.Is(err, service.ErrInvalidSoShell):
			response.Error(c, http.StatusBadRequest, 40013, err.Error())
		case errors.Is(err, service.ErrInvalidSoStrength):
			response.Error(c, http.StatusBadRequest, 40014, err.Error())
		default:
			response.Error(c, http.StatusInternalServerError, 50010, "保存策略失败")
		}
		return
	}

	response.Success(c, http.StatusOK, saved)
}
