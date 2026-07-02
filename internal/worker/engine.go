package worker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"beetleshield-backend/internal/model"
)

type EngineRunRequest struct {
	Command []string
	WorkDir string
}

type EngineRunner interface {
	Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error
}

type DPTRunner struct{}

func (DPTRunner) Run(ctx context.Context, req EngineRunRequest, onLine func(model.HardeningLogLevel, string)) error {
	if len(req.Command) == 0 {
		return fmt.Errorf("empty engine command")
	}

	cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
	cmd.Dir = req.WorkDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go scanEngineLines(stdout, model.HardeningLogLevelInfo, onLine, &wg, errCh)
	go scanEngineLines(stderr, model.HardeningLogLevelError, onLine, &wg, errCh)

	// The stdout/stderr pipes must be fully drained before calling cmd.Wait():
	// Wait closes them as soon as it sees the process exit, and racing that
	// close against the scanning goroutines' still-in-flight Read calls
	// produces an intermittent "read |0: file already closed" error instead
	// of a clean EOF. Draining first is safe here because the pipes reach
	// EOF on their own once the child process exits and closes its ends,
	// independent of when the parent calls Wait.
	wg.Wait()
	close(errCh)
	waitErr := cmd.Wait()

	var scanErr error
	for err := range errCh {
		scanErr = errors.Join(scanErr, err)
	}
	if scanErr != nil {
		return errors.Join(waitErr, scanErr)
	}
	return waitErr
}

func scanEngineLines(reader io.Reader, fallback model.HardeningLogLevel, onLine func(model.HardeningLogLevel, string), wg *sync.WaitGroup, errCh chan<- error) {
	defer wg.Done()

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if onLine != nil {
			onLine(classifyEngineLine(line, fallback), line)
		}
	}
	if err := scanner.Err(); err != nil {
		errCh <- err
	}
}

func classifyEngineLine(line string, fallback model.HardeningLogLevel) model.HardeningLogLevel {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "ERROR"), strings.Contains(upper, "EXCEPTION"), strings.Contains(upper, "FAILED"):
		return model.HardeningLogLevelError
	case strings.Contains(upper, "WARN"):
		return model.HardeningLogLevelWarn
	case strings.Contains(upper, "SUCCESS"), strings.Contains(upper, "ALL DONE"):
		return model.HardeningLogLevelSuccess
	default:
		return fallback
	}
}
