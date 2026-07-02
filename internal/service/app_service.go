package service

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/manifest"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
)

var (
	ErrUnsupportedFileType       = errors.New("unsupported file type, only .apk and .aab are allowed")
	ErrFileTooLarge              = errors.New("file exceeds the maximum allowed size")
	ErrMissingPackageInfo        = errors.New("could not determine package name/version, please provide them manually")
	ErrAppNotFound               = errors.New("app not found")
	ErrAppHasActiveHardeningTask = errors.New("app has an active hardening task and cannot be deleted")
)

type UploadInput struct {
	FileHeader        *multipart.FileHeader
	Tag               model.AppTag
	ManualPackageName string
	ManualVersion     string
	UploadedBy        uint
}

type AppService struct {
	appRepo         *repository.AppRepository
	hardeningRepo   *repository.HardeningRepository
	storage         *storage.MinioStorage
	maxUploadSizeMB int64
}

func NewAppService(appRepo *repository.AppRepository, hardeningRepo *repository.HardeningRepository, storage *storage.MinioStorage, maxUploadSizeMB int64) *AppService {
	return &AppService{appRepo: appRepo, hardeningRepo: hardeningRepo, storage: storage, maxUploadSizeMB: maxUploadSizeMB}
}

// Upload 是一个处理应用文件上传的方法
// 它接收上下文和上传输入参数，返回上传的应用模型或错误
// AppService 的 Upload 方法用于处理应用文件上传
func (s *AppService) Upload(ctx context.Context, input UploadInput) (*model.App, error) {
	// 获取上传文件的扩展名并转换为小写
	ext := strings.ToLower(filepath.Ext(input.FileHeader.Filename))
	// 检查文件扩展名是否为支持的类型（.apk 或 .aab）
	if ext != ".apk" && ext != ".aab" {
		return nil, ErrUnsupportedFileType
	}

	// 计算允许的最大文件大小（MB转换为字节）
	maxBytes := s.maxUploadSizeMB * 1024 * 1024
	// 检查文件大小是否超过限制
	if input.FileHeader.Size > maxBytes {
		return nil, ErrFileTooLarge
	}

	// 打开上传的文件
	src, err := input.FileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("open uploaded file: %w", err)
	}
	defer src.Close() // 确保文件最终被关闭

	// 创建临时文件，文件名包含随机数和原始扩展名
	tmpFile, err := os.CreateTemp("", "beetleshield-upload-*"+ext)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // 确保临时文件最终被删除
	defer tmpFile.Close()    // 确保临时文件最终被关闭

	// 创建MD5和SHA256哈希计算器
	md5Hash := md5.New()
	sha256Hash := sha256.New()
	// 创建多写入器，同时写入临时文件、计算MD5和SHA256
	multiWriter := io.MultiWriter(tmpFile, md5Hash, sha256Hash)

	// 将上传文件内容复制到多写入器
	if _, err := io.Copy(multiWriter, src); err != nil {
		return nil, fmt.Errorf("write temp file: %w", err)
	}

	// 获取手动输入的包名和版本号
	packageName := input.ManualPackageName
	version := input.ManualVersion

	// 如果是APK文件，尝试解析APK获取包名和版本号
	if ext == ".apk" {
		info, parseErr := manifest.ParseAPK(tmpPath)
		if parseErr == nil {
			// 如果手动包名为空，使用解析出的包名
			if packageName == "" {
				packageName = info.PackageName
			}
			if version == "" {
				version = info.VersionName
			}
		}
	}

	if packageName == "" || version == "" {
		return nil, ErrMissingPackageInfo
	}

	md5Sum := hex.EncodeToString(md5Hash.Sum(nil))
	sha256Sum := hex.EncodeToString(sha256Hash.Sum(nil))

	// 生成存储对象键，格式为: 包名/SHA256前12位/文件名
	objectKey := fmt.Sprintf("%s/%s/%s", packageName, sha256Sum[:12], input.FileHeader.Filename)

	// 将临时文件指针重置到文件开头
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek temp file: %w", err)
	}

	// 设置文件内容类型：.apk 使用标准 APK MIME 类型，.aab 没有广泛注册的标准类型，使用通用二进制类型
	contentType := "application/octet-stream"
	if ext == ".apk" {
		contentType = "application/vnd.android.package-archive"
	}
	// 将文件上传到存储系统
	if err := s.storage.PutObject(ctx, objectKey, tmpFile, input.FileHeader.Size, contentType); err != nil {
		return nil, fmt.Errorf("upload to storage: %w", err)
	}

	// 创建应用记录
	app := &model.App{
		Name:        strings.TrimSuffix(input.FileHeader.Filename, ext), // 去除扩展名的文件名
		PackageName: packageName,
		Version:     version,
		Tag:         input.Tag,
		Status:      model.AppStatusUnprotected,
		FileSize:    input.FileHeader.Size,
		ObjectKey:   objectKey,
		MD5:         md5Sum,
		SHA256:      sha256Sum,
		UploadedBy:  input.UploadedBy,
	}

	// 保存应用记录到数据库
	if err := s.appRepo.Create(app); err != nil {
		// 如果保存失败，删除已上传的文件
		_ = s.storage.DeleteObject(ctx, objectKey)
		return nil, fmt.Errorf("save app record: %w", err)
	}

	// 返回创建的应用记录
	return app, nil
}

func (s *AppService) List(filter repository.AppListFilter) ([]model.App, int64, error) {
	return s.appRepo.List(filter)
}

func (s *AppService) Get(id uint) (*model.App, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return nil, ErrAppNotFound
	}
	return app, nil
}

func (s *AppService) Delete(ctx context.Context, id uint) error {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return ErrAppNotFound
	}

	hasActive, err := s.hardeningRepo.HasActiveTaskForApp(id)
	if err != nil {
		return fmt.Errorf("check active hardening task: %w", err)
	}
	if hasActive {
		return ErrAppHasActiveHardeningTask
	}

	if err := s.appRepo.Delete(id); err != nil {
		return fmt.Errorf("delete app record: %w", err)
	}
	_ = s.storage.DeleteObject(ctx, app.ObjectKey)
	return nil
}

func (s *AppService) DownloadURL(ctx context.Context, id uint) (string, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return "", ErrAppNotFound
	}
	return s.storage.PresignedDownloadURL(ctx, app.ObjectKey, 15*time.Minute)
}
