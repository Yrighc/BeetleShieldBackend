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
	ErrUnsupportedFileType = errors.New("unsupported file type, only .apk and .aab are allowed")
	ErrFileTooLarge        = errors.New("file exceeds the maximum allowed size")
	ErrMissingPackageInfo  = errors.New("could not determine package name/version, please provide them manually")
	ErrAppNotFound         = errors.New("app not found")
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
	storage         *storage.MinioStorage
	maxUploadSizeMB int64
}

func NewAppService(appRepo *repository.AppRepository, storage *storage.MinioStorage, maxUploadSizeMB int64) *AppService {
	return &AppService{appRepo: appRepo, storage: storage, maxUploadSizeMB: maxUploadSizeMB}
}

func (s *AppService) Upload(ctx context.Context, input UploadInput) (*model.App, error) {
	ext := strings.ToLower(filepath.Ext(input.FileHeader.Filename))
	if ext != ".apk" && ext != ".aab" {
		return nil, ErrUnsupportedFileType
	}

	maxBytes := s.maxUploadSizeMB * 1024 * 1024
	if input.FileHeader.Size > maxBytes {
		return nil, ErrFileTooLarge
	}

	src, err := input.FileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("open uploaded file: %w", err)
	}
	defer src.Close()

	tmpFile, err := os.CreateTemp("", "beetleshield-upload-*"+ext)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	defer tmpFile.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()
	multiWriter := io.MultiWriter(tmpFile, md5Hash, sha256Hash)

	if _, err := io.Copy(multiWriter, src); err != nil {
		return nil, fmt.Errorf("write temp file: %w", err)
	}

	packageName := input.ManualPackageName
	version := input.ManualVersion

	if ext == ".apk" {
		info, parseErr := manifest.ParseAPK(tmpPath)
		if parseErr == nil {
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

	objectKey := fmt.Sprintf("%s/%s/%s", packageName, sha256Sum[:12], input.FileHeader.Filename)

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek temp file: %w", err)
	}

	contentType := "application/vnd.android.package-archive"
	if err := s.storage.PutObject(ctx, objectKey, tmpFile, input.FileHeader.Size, contentType); err != nil {
		return nil, fmt.Errorf("upload to storage: %w", err)
	}

	app := &model.App{
		Name:        strings.TrimSuffix(input.FileHeader.Filename, ext),
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

	if err := s.appRepo.Create(app); err != nil {
		_ = s.storage.DeleteObject(ctx, objectKey)
		return nil, fmt.Errorf("save app record: %w", err)
	}

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
	if err := s.storage.DeleteObject(ctx, app.ObjectKey); err != nil {
		return fmt.Errorf("delete storage object: %w", err)
	}
	return s.appRepo.Delete(id)
}

func (s *AppService) DownloadURL(ctx context.Context, id uint) (string, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return "", ErrAppNotFound
	}
	return s.storage.PresignedDownloadURL(ctx, app.ObjectKey, 15*time.Minute)
}
