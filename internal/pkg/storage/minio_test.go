package storage

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func newTestStorage(t *testing.T) *MinioStorage {
	t.Helper()
	s, err := NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v (is `make dev-up` running?)", err)
	}
	return s
}

func TestPutAndDeleteObject(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	objectKey := "unit-test/hello.txt"
	content := []byte("hello beetleshield")

	if err := s.PutObject(ctx, objectKey, bytes.NewReader(content), int64(len(content)), "text/plain"); err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}

	downloadURL, err := s.PresignedDownloadURL(ctx, objectKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("PresignedDownloadURL() error = %v", err)
	}
	if downloadURL == "" {
		t.Error("expected non-empty presigned URL")
	}

	if err := s.DeleteObject(ctx, objectKey); err != nil {
		t.Fatalf("DeleteObject() error = %v", err)
	}
}
