package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type APIRequestLogHandler struct {
	svc *service.APIRequestLogService
}

func NewAPIRequestLogHandler(svc *service.APIRequestLogService) *APIRequestLogHandler {
	return &APIRequestLogHandler{svc: svc}
}

func (h *APIRequestLogHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	actorUserID, _ := strconv.ParseUint(c.DefaultQuery("actorUserId", "0"), 10, 64)

	filter := repository.APIRequestLogListFilter{
		Method:      c.Query("method"),
		Path:        c.Query("path"),
		ActorUserID: uint(actorUserID),
		Page:        page,
		PageSize:    pageSize,
	}

	if statusParam := c.Query("status"); statusParam != "" {
		status, err := strconv.Atoi(statusParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40040, "非法的状态码")
			return
		}
		filter.Status = &status
	}
	if startParam := c.Query("startTime"); startParam != "" {
		t, err := time.Parse(time.RFC3339, startParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40041, "非法的开始时间")
			return
		}
		filter.StartTime = &t
	}
	if endParam := c.Query("endTime"); endParam != "" {
		t, err := time.Parse(time.RFC3339, endParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40042, "非法的结束时间")
			return
		}
		filter.EndTime = &t
	}

	logs, total, err := h.svc.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50040, "查询 API 请求日志失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{"items": logs, "total": total})
}
