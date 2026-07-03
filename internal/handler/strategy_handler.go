package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/repository"
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
	Name               string                    `json:"name"`
	Description        string                    `json:"description"`
	Frida              bool                      `json:"frida"`
	Xposed             bool                      `json:"xposed"`
	Emulator           bool                      `json:"emulator"`
	DexLevel           model.DexObfuscationLevel `json:"dexLevel" binding:"required"`
	StringEncrypt      bool                      `json:"stringEncrypt"`
	ResMix             bool                      `json:"resMix"`
	SoShell            model.SoShellType         `json:"soShell" binding:"required"`
	SoStrength         int                       `json:"soStrength"`
	TargetSos          []string                  `json:"targetSos"`
	RootDetect         bool                      `json:"rootDetect"`
	Signature          bool                      `json:"signature"`
	SigPolicy          model.SigPolicy           `json:"sigPolicy" binding:"required"`
	AntiHook           bool                      `json:"antiHook"`
	ResEncrypt         bool                      `json:"resEncrypt"`
	ScreenshotProtect  bool                      `json:"screenshotProtect"`
	FileIntegrityCheck bool                      `json:"fileIntegrityCheck"`
	ProxyDetect        bool                      `json:"proxyDetect"`
	VMPRulesText       string                    `json:"vmpRulesText"`
}

func (h *StrategyHandler) SaveCurrent(c *gin.Context) {
	var req saveStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40011, err.Error())
		return
	}

	userID := c.GetUint(middleware.ContextUserIDKey)

	saved, err := h.strategyService.SaveCurrent(service.SaveStrategyInput{
		Frida: req.Frida, Xposed: req.Xposed, Emulator: req.Emulator,
		DexLevel: req.DexLevel, StringEncrypt: req.StringEncrypt, ResMix: req.ResMix,
		SoShell: req.SoShell, SoStrength: req.SoStrength, TargetSos: req.TargetSos,
		RootDetect: req.RootDetect, Signature: req.Signature, SigPolicy: req.SigPolicy, AntiHook: req.AntiHook, ResEncrypt: req.ResEncrypt,
		ScreenshotProtect: req.ScreenshotProtect, FileIntegrityCheck: req.FileIntegrityCheck, ProxyDetect: req.ProxyDetect,
		VMPRulesText: req.VMPRulesText,
	}, userID, c.ClientIP())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidDexLevel):
			response.Error(c, http.StatusBadRequest, 40012, err.Error())
		case errors.Is(err, service.ErrInvalidSoShell):
			response.Error(c, http.StatusBadRequest, 40013, err.Error())
		case errors.Is(err, service.ErrInvalidSoStrength):
			response.Error(c, http.StatusBadRequest, 40014, err.Error())
		case errors.Is(err, service.ErrInvalidSigPolicy):
			response.Error(c, http.StatusBadRequest, 40017, err.Error())
		default:
			response.Error(c, http.StatusInternalServerError, 50010, "保存策略失败")
		}
		return
	}

	response.Success(c, http.StatusOK, saved)
}

func (h *StrategyHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	items, total, err := h.strategyService.List(repository.StrategyListFilter{
		Search:   c.Query("search"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50011, "查询策略列表失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": items,
		"total": total,
	})
}

func (h *StrategyHandler) Create(c *gin.Context) {
	var req saveStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40011, err.Error())
		return
	}

	saved, err := h.strategyService.Create(strategyPayloadFromRequest(req), c.GetUint(middleware.ContextUserIDKey), c.ClientIP())
	if err != nil {
		writeStrategyMutationError(c, err)
		return
	}

	response.Success(c, http.StatusOK, saved)
}

func (h *StrategyHandler) Get(c *gin.Context) {
	id, ok := parseStrategyIDParam(c)
	if !ok {
		return
	}

	strategy, err := h.strategyService.Get(id)
	if err != nil {
		if errors.Is(err, service.ErrStrategyNotFound) {
			response.Error(c, http.StatusNotFound, 40412, "加固策略不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50012, "查询策略失败")
		return
	}

	response.Success(c, http.StatusOK, strategy)
}

func (h *StrategyHandler) Update(c *gin.Context) {
	id, ok := parseStrategyIDParam(c)
	if !ok {
		return
	}

	var req saveStrategyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40011, err.Error())
		return
	}

	updated, err := h.strategyService.Update(id, strategyPayloadFromRequest(req), c.GetUint(middleware.ContextUserIDKey), c.ClientIP())
	if err != nil {
		writeStrategyMutationError(c, err)
		return
	}

	response.Success(c, http.StatusOK, updated)
}

func (h *StrategyHandler) Delete(c *gin.Context) {
	id, ok := parseStrategyIDParam(c)
	if !ok {
		return
	}

	if err := h.strategyService.Delete(id, c.GetUint(middleware.ContextUserIDKey), c.ClientIP()); err != nil {
		writeStrategyMutationError(c, err)
		return
	}

	response.Success(c, http.StatusOK, gin.H{"deleted": true})
}

func strategyPayloadFromRequest(req saveStrategyRequest) service.StrategyPayloadInput {
	return service.StrategyPayloadInput{
		Name:        req.Name,
		Description: req.Description,
		SaveStrategyInput: service.SaveStrategyInput{
			Frida: req.Frida, Xposed: req.Xposed, Emulator: req.Emulator,
			DexLevel: req.DexLevel, StringEncrypt: req.StringEncrypt, ResMix: req.ResMix,
			SoShell: req.SoShell, SoStrength: req.SoStrength, TargetSos: req.TargetSos,
			RootDetect: req.RootDetect, Signature: req.Signature, SigPolicy: req.SigPolicy, AntiHook: req.AntiHook, ResEncrypt: req.ResEncrypt,
			ScreenshotProtect: req.ScreenshotProtect, FileIntegrityCheck: req.FileIntegrityCheck, ProxyDetect: req.ProxyDetect,
			VMPRulesText: req.VMPRulesText,
		},
	}
}

func writeStrategyMutationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrStrategyNameRequired):
		response.Error(c, http.StatusBadRequest, 40015, err.Error())
	case errors.Is(err, service.ErrInvalidDexLevel):
		response.Error(c, http.StatusBadRequest, 40012, err.Error())
	case errors.Is(err, service.ErrInvalidSoShell):
		response.Error(c, http.StatusBadRequest, 40013, err.Error())
	case errors.Is(err, service.ErrInvalidSoStrength):
		response.Error(c, http.StatusBadRequest, 40014, err.Error())
	case errors.Is(err, service.ErrInvalidSigPolicy):
		response.Error(c, http.StatusBadRequest, 40017, err.Error())
	case errors.Is(err, service.ErrStrategyNameExists):
		response.Error(c, http.StatusConflict, 40912, "策略名称已存在")
	case errors.Is(err, service.ErrStrategyNotFound):
		response.Error(c, http.StatusNotFound, 40412, "加固策略不存在")
	case errors.Is(err, service.ErrDefaultStrategyDelete):
		response.Error(c, http.StatusConflict, 40913, "默认策略不能删除")
	default:
		response.Error(c, http.StatusInternalServerError, 50010, "保存策略失败")
	}
}

func parseStrategyIDParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40016, "非法策略 ID")
		return 0, false
	}
	return uint(id), true
}
