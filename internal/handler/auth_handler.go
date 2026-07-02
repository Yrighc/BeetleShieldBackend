package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40001, err.Error())
		return
	}

	token, user, err := h.authService.Login(req.Email, req.Password, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			response.Error(c, http.StatusUnauthorized, 40102, "邮箱或密码错误")
			return
		}
		if errors.Is(err, service.ErrUserDisabled) {
			response.Error(c, http.StatusForbidden, 40301, "账号已被禁用")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50000, "登录失败，请稍后重试")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID := c.GetUint(middleware.ContextUserIDKey)
	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		response.Error(c, http.StatusNotFound, 40401, "用户不存在")
		return
	}
	response.Success(c, http.StatusOK, user)
}
