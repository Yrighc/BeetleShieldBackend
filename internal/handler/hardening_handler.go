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

type HardeningHandler struct {
	svc *service.HardeningService
}

func NewHardeningHandler(svc *service.HardeningService) *HardeningHandler {
	return &HardeningHandler{svc: svc}
}

type createHardeningTaskRequest struct {
	AppID                    uint            `json:"appId" binding:"required"`
	StrategyName             string          `json:"strategyName"`
	StrategySnapshot         *model.Strategy `json:"strategySnapshot"`
	VMPRulesText             string          `json:"vmpRulesText"`
	EnableFileIntegrityCheck bool            `json:"enableFileIntegrityCheck"`
	EnableProxyDetect        bool            `json:"enableProxyDetect"`
}

func (h *HardeningHandler) Create(c *gin.Context) {
	var req createHardeningTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40020, err.Error())
		return
	}

	detail, err := h.svc.Create(c.Request.Context(), service.CreateHardeningTaskInput{
		AppID:                    req.AppID,
		StrategyName:             req.StrategyName,
		StrategySnapshot:         req.StrategySnapshot,
		VMPRulesText:             req.VMPRulesText,
		EnableFileIntegrityCheck: req.EnableFileIntegrityCheck,
		EnableProxyDetect:        req.EnableProxyDetect,
		CreatedBy:                c.GetUint(middleware.ContextUserIDKey),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrHardeningAppNotFound):
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
		case errors.Is(err, service.ErrHardeningActiveTaskExists):
			response.Error(c, http.StatusConflict, 40910, "应用已有进行中的加固任务")
		default:
			response.Error(c, http.StatusInternalServerError, 50020, "创建加固任务失败")
		}
		return
	}

	response.Success(c, http.StatusOK, detail)
}

func (h *HardeningHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	appID, _ := strconv.ParseUint(c.DefaultQuery("appId", "0"), 10, 64)

	items, total, err := h.svc.List(repository.HardeningListFilter{
		Status:   c.Query("status"),
		AppID:    uint(appID),
		Search:   c.Query("search"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50021, "查询加固任务失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": items,
		"total": total,
	})
}

func (h *HardeningHandler) Get(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}

	detail, err := h.svc.Get(id)
	if err != nil {
		if errors.Is(err, service.ErrHardeningTaskNotFound) {
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50021, "查询加固任务失败")
		return
	}

	response.Success(c, http.StatusOK, detail)
}

func (h *HardeningHandler) Logs(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}

	afterID, _ := strconv.ParseUint(c.DefaultQuery("afterId", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))

	logs, err := h.svc.Logs(id, repository.HardeningLogFilter{
		StepKey: model.HardeningStepKey(c.Query("stepKey")),
		AfterID: uint(afterID),
		Limit:   limit,
	})
	if err != nil {
		if errors.Is(err, service.ErrHardeningTaskNotFound) {
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50021, "查询加固日志失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{"items": logs})
}

func (h *HardeningHandler) DownloadURL(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}

	url, err := h.svc.DownloadURL(c.Request.Context(), id, c.Query("artifact"))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrHardeningTaskNotFound):
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
		case errors.Is(err, service.ErrHardeningArtifactNotFound):
			response.Error(c, http.StatusNotFound, 40411, "加固产物不存在")
		case errors.Is(err, service.ErrInvalidHardeningArtifact):
			response.Error(c, http.StatusBadRequest, 40020, "非法产物类型")
		default:
			response.Error(c, http.StatusInternalServerError, 50022, "生成产物下载链接失败")
		}
		return
	}

	response.Success(c, http.StatusOK, gin.H{"url": url})
}

func (h *HardeningHandler) AppHistory(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}

	items, err := h.svc.History(id)
	if err != nil {
		if errors.Is(err, service.ErrHardeningAppNotFound) {
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50021, "查询应用加固历史失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{"items": items})
}

func parseUintParam(c *gin.Context, name string) (uint, bool) {
	id, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40021, "非法任务 ID")
		return 0, false
	}
	return uint(id), true
}
