package worker

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"beetleshield-backend/internal/model"
)

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}

func TestScanEngineLinesReturnsScannerError(t *testing.T) {
	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	wg.Add(1)

	go scanEngineLines(&errorReader{err: errors.New("boom")}, model.HardeningLogLevelInfo, nil, &wg, errCh)
	wg.Wait()
	close(errCh)

	var err error
	for scanErr := range errCh {
		err = errors.Join(err, scanErr)
	}

	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("scanEngineLines() error = %v, want scanner error", err)
	}
}
