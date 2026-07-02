package service_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"os"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func buildFileHeader(t *testing.T, fieldName, fileName string, content []byte) *multipart.FileHeader {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	r := multipart.NewReader(&buf, w.Boundary())
	form, err := r.ReadForm(int64(len(content)) + 1024)
	if err != nil {
		t.Fatalf("ReadForm() error = %v", err)
	}
	t.Cleanup(func() { form.RemoveAll() })

	return form.File[fieldName][0]
}

func setupAppService(t *testing.T) *service.AppService {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)

	st, err := storage.NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := st.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v (is `make dev-up` running?)", err)
	}

	return service.NewAppService(appRepo, hardeningRepo, st, 10)
}

func TestAppService_Upload_ManualPackageInfo(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "notreal.aab", []byte("not a real aab, just bytes for testing"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svctest.aabapp",
		ManualVersion:     "2.0.0",
		UploadedBy:        1,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID) })

	if app.PackageName != "com.svctest.aabapp" {
		t.Errorf("PackageName = %q, want %q", app.PackageName, "com.svctest.aabapp")
	}
	if app.Status != model.AppStatusUnprotected {
		t.Errorf("Status = %q, want %q", app.Status, model.AppStatusUnprotected)
	}
	if app.MD5 == "" || app.SHA256 == "" {
		t.Error("expected non-empty MD5/SHA256")
	}

	fetched, err := svc.Get(app.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if fetched.ID != app.ID {
		t.Errorf("Get() returned different app")
	}

	downloadURL, err := svc.DownloadURL(ctx, app.ID)
	if err != nil {
		t.Fatalf("DownloadURL() error = %v", err)
	}
	if downloadURL == "" {
		t.Error("expected non-empty download URL")
	}
}

func TestAppService_Upload_AutoParsesAPKPackageInfo(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	content, err := os.ReadFile("../pkg/manifest/testdata/helloworld.apk")
	if err != nil {
		t.Fatalf("read fixture apk: %v", err)
	}
	fh := buildFileHeader(t, "file", "helloworld.apk", content)

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID) })

	if app.PackageName != "com.example.helloworld" {
		t.Errorf("PackageName = %q, want %q (auto-parsed)", app.PackageName, "com.example.helloworld")
	}
}

func TestAppService_Upload_MissingPackageInfoForAAB(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "noinfo.aab", []byte("bytes without package info"))

	_, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != service.ErrMissingPackageInfo {
		t.Errorf("err = %v, want %v", err, service.ErrMissingPackageInfo)
	}
}

func TestAppService_Upload_RejectsUnsupportedExtension(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "app.exe", []byte("nope"))

	_, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != service.ErrUnsupportedFileType {
		t.Errorf("err = %v, want %v", err, service.ErrUnsupportedFileType)
	}
}
