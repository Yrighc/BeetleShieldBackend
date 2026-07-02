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

type AppHandler struct {
	appService *service.AppService
}

func NewAppHandler(appService *service.AppService) *AppHandler {
	return &AppHandler{appService: appService}
}

var validAppTags = map[model.AppTag]bool{
	model.AppTagFinance:   true,
	model.AppTagGame:      true,
	model.AppTagTool:      true,
	model.AppTagEcommerce: true,
}

func (h *AppHandler) Upload(c *gin.Context) {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40002, "缺少上传文件")
		return
	}

	tag := model.AppTag(c.PostForm("tag"))
	if !validAppTags[tag] {
		response.Error(c, http.StatusBadRequest, 40006, "无效的应用标签")
		return
	}

	userID := c.GetUint(middleware.ContextUserIDKey)

	input := service.UploadInput{
		FileHeader:        fileHeader,
		Tag:               tag,
		ManualPackageName: c.PostForm("packageName"),
		ManualVersion:     c.PostForm("version"),
		UploadedBy:        userID,
	}

	app, err := h.appService.Upload(c.Request.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUnsupportedFileType):
			response.Error(c, http.StatusBadRequest, 40003, err.Error())
		case errors.Is(err, service.ErrFileTooLarge):
			response.Error(c, http.StatusBadRequest, 40004, err.Error())
		case errors.Is(err, service.ErrMissingPackageInfo):
			response.Error(c, http.StatusUnprocessableEntity, 42201, err.Error())
		default:
			response.Error(c, http.StatusInternalServerError, 50001, "上传失败，请稍后重试")
		}
		return
	}

	response.Success(c, http.StatusOK, app)
}

func (h *AppHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	filter := repository.AppListFilter{
		Search:   c.Query("search"),
		Status:   c.Query("status"),
		Tag:      c.Query("tag"),
		Page:     page,
		PageSize: pageSize,
	}

	apps, total, err := h.appService.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50002, "查询应用列表失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": apps,
		"total": total,
	})
}

func (h *AppHandler) Get(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40005, "非法的应用 ID")
		return
	}

	app, err := h.appService.Get(uint(id))
	if err != nil {
		response.Error(c, http.StatusNotFound, 40402, "应用不存在")
		return
	}

	response.Success(c, http.StatusOK, app)
}

func (h *AppHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40005, "非法的应用 ID")
		return
	}

	if err := h.appService.Delete(c.Request.Context(), uint(id)); err != nil {
		switch {
		case errors.Is(err, service.ErrAppNotFound):
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
		case errors.Is(err, service.ErrAppHasActiveHardeningTask):
			response.Error(c, http.StatusConflict, 40902, "应用存在进行中的加固任务，无法删除")
		default:
			response.Error(c, http.StatusInternalServerError, 50003, "删除应用失败")
		}
		return
	}

	response.Success(c, http.StatusOK, nil)
}

func (h *AppHandler) DownloadURL(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40005, "非法的应用 ID")
		return
	}

	downloadURL, err := h.appService.DownloadURL(c.Request.Context(), uint(id))
	if err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50004, "生成下载链接失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{"url": downloadURL})
}
