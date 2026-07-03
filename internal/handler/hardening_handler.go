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
	svc          *service.HardeningService
	dashboardSvc *service.DashboardService
}

func NewHardeningHandler(svc *service.HardeningService, dashboardSvc *service.DashboardService) *HardeningHandler {
	return &HardeningHandler{svc: svc, dashboardSvc: dashboardSvc}
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
		IP:                       c.ClientIP(),
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
	// -1 means "not provided" and lets the repository apply its own default;
	// an explicit limit=0 is a real request for zero rows and must be
	// distinguishable from "the client didn't pass limit at all".
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "-1"))

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

	url, err := h.svc.DownloadURL(c.Request.Context(), id, c.Query("artifact"), c.GetUint(middleware.ContextUserIDKey), c.ClientIP())
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

func (h *HardeningHandler) GetReport(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}

	report, err := h.svc.GetReport(id)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrHardeningTaskNotFound):
			response.Error(c, http.StatusNotFound, 40410, "加固任务不存在")
		case errors.Is(err, service.ErrHardeningReportNotReady):
			response.Error(c, http.StatusConflict, 40911, "加固任务未完成，无法生成报告")
		default:
			response.Error(c, http.StatusInternalServerError, 50023, "生成加固报告失败")
		}
		return
	}

	response.Success(c, http.StatusOK, report)
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

func (h *HardeningHandler) GetOverview(c *gin.Context) {
	overview, err := h.dashboardSvc.GetOverview()
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50024, "查询系统总览失败")
		return
	}

	response.Success(c, http.StatusOK, overview)
}

func parseUintParam(c *gin.Context, name string) (uint, bool) {
	id, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40021, "非法任务 ID")
		return 0, false
	}
	return uint(id), true
}
