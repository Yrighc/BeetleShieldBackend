package storage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestMinioStorage_GetObjectToFile(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	objectKey := fmt.Sprintf("hardening-storage-test/%d-source.txt", time.Now().UnixNano())
	body := strings.NewReader("download me")
	if err := st.PutObject(ctx, objectKey, body, int64(body.Len()), "text/plain"); err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	t.Cleanup(func() {
		_ = st.DeleteObject(ctx, objectKey)
	})

	destination := filepath.Join(t.TempDir(), "downloaded.txt")
	if err := st.GetObjectToFile(ctx, objectKey, destination); err != nil {
		t.Fatalf("GetObjectToFile() error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "download me" {
		t.Fatalf("downloaded content = %q", string(got))
	}
}
