package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// StatusScannerPort scans project state and returns the result with a recommendation.
type StatusScannerPort interface {
	ScanProject(ctx context.Context, dir string) (stateData any, nextCommand string, err error)
}

// StatusDeps groups the port interfaces for the status use case.
type StatusDeps struct {
	Scanner StatusScannerPort
}

// Status scans project state and returns the status with a recommended next command.
func Status(
	ctx context.Context,
	req domain.StatusRequest,
	deps StatusDeps,
) (domain.StatusResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.StatusResponse{}, fmt.Errorf("status: %w", err)
	}

	stateData, nextCmd, err := deps.Scanner.ScanProject(ctx, req.Dir)
	if err != nil {
		return domain.StatusResponse{}, fmt.Errorf("status: %w", err)
	}

	return domain.StatusResponse{
		StateData:   stateData,
		NextCommand: nextCmd,
	}, nil
}
