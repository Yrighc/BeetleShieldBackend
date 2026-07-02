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

type UserHandler struct {
	userService *service.UserService
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

var validUserRoles = map[model.UserRole]bool{
	model.RoleAdmin:     true,
	model.RoleDeveloper: true,
	model.RoleAuditor:   true,
}

var validUserStatuses = map[model.UserStatus]bool{
	model.UserStatusActive:   true,
	model.UserStatusDisabled: true,
}

func (h *UserHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	filter := repository.UserListFilter{
		Search:   c.Query("search"),
		Role:     c.Query("role"),
		Page:     page,
		PageSize: pageSize,
	}

	users, total, err := h.userService.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50005, "查询用户列表失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": users,
		"total": total,
	})
}

type createUserRequest struct {
	Name       string         `json:"name" binding:"required"`
	Email      string         `json:"email" binding:"required,email"`
	Password   string         `json:"password" binding:"required,min=8"`
	Role       model.UserRole `json:"role" binding:"required"`
	Department string         `json:"department"`
}

func (h *UserHandler) Create(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40007, err.Error())
		return
	}
	if !validUserRoles[req.Role] {
		response.Error(c, http.StatusBadRequest, 40008, "无效的用户角色")
		return
	}

	user, err := h.userService.Create(service.CreateUserInput{
		Name:       req.Name,
		Email:      req.Email,
		Password:   req.Password,
		Role:       req.Role,
		Department: req.Department,
	})
	if err != nil {
		if errors.Is(err, service.ErrEmailAlreadyExists) {
			response.Error(c, http.StatusConflict, 40901, "邮箱已被使用")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50006, "创建用户失败")
		return
	}

	response.Success(c, http.StatusOK, user)
}

type updateUserRequest struct {
	Name       *string         `json:"name"`
	Department *string         `json:"department"`
	Role       *model.UserRole `json:"role"`
}

func (h *UserHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40009, "非法的用户 ID")
		return
	}

	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40007, err.Error())
		return
	}
	if req.Role != nil && !validUserRoles[*req.Role] {
		response.Error(c, http.StatusBadRequest, 40008, "无效的用户角色")
		return
	}

	user, err := h.userService.Update(uint(id), service.UpdateUserInput{
		Name:       req.Name,
		Department: req.Department,
		Role:       req.Role,
	})
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			response.Error(c, http.StatusNotFound, 40403, "用户不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50007, "更新用户失败")
		return
	}

	response.Success(c, http.StatusOK, user)
}

type updateUserStatusRequest struct {
	Status model.UserStatus `json:"status" binding:"required"`
}

func (h *UserHandler) UpdateStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40009, "非法的用户 ID")
		return
	}

	var req updateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40007, err.Error())
		return
	}
	if !validUserStatuses[req.Status] {
		response.Error(c, http.StatusBadRequest, 40010, "无效的用户状态")
		return
	}

	currentUserID := c.GetUint(middleware.ContextUserIDKey)

	if err := h.userService.UpdateStatus(uint(id), req.Status, currentUserID); err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			response.Error(c, http.StatusNotFound, 40403, "用户不存在")
		case errors.Is(err, service.ErrCannotDisableSelf):
			response.Error(c, http.StatusForbidden, 40303, "不能禁用自己的账号")
		default:
			response.Error(c, http.StatusInternalServerError, 50008, "更新用户状态失败")
		}
		return
	}

	response.Success(c, http.StatusOK, nil)
}
