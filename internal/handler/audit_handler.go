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

type AuditHandler struct {
	auditService *service.AuditService
}

func NewAuditHandler(auditService *service.AuditService) *AuditHandler {
	return &AuditHandler{auditService: auditService}
}

func (h *AuditHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	actorUserID, _ := strconv.ParseUint(c.DefaultQuery("actorUserId", "0"), 10, 64)

	filter := repository.AuditListFilter{
		ActorUserID: uint(actorUserID),
		Action:      c.Query("action"),
		TargetType:  c.Query("targetType"),
		Page:        page,
		PageSize:    pageSize,
	}

	if successParam := c.Query("success"); successParam != "" {
		success := successParam == "true"
		filter.Success = &success
	}
	if startParam := c.Query("startTime"); startParam != "" {
		startTime, err := time.Parse(time.RFC3339, startParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40030, "非法的开始时间")
			return
		}
		filter.StartTime = &startTime
	}
	if endParam := c.Query("endTime"); endParam != "" {
		endTime, err := time.Parse(time.RFC3339, endParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40031, "非法的结束时间")
			return
		}
		filter.EndTime = &endTime
	}

	logs, total, err := h.auditService.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50030, "查询审计日志失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": logs,
		"total": total,
	})
}
