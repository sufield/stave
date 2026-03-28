package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// DoctorCheckRunnerPort runs environment diagnostic checks.
type DoctorCheckRunnerPort interface {
	RunChecks(ctx context.Context, cwd, binaryPath string) ([]domain.DoctorCheck, bool, error)
}

// DoctorDeps groups the port interfaces for the doctor use case.
type DoctorDeps struct {
	CheckRunner DoctorCheckRunnerPort
}

// Doctor runs environment readiness checks and returns the results.
func Doctor(
	ctx context.Context,
	req domain.DoctorRequest,
	deps DoctorDeps,
) (domain.DoctorResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.DoctorResponse{}, fmt.Errorf("doctor: %w", err)
	}

	checks, allPassed, err := deps.CheckRunner.RunChecks(ctx, req.Cwd, req.BinaryPath)
	if err != nil {
		return domain.DoctorResponse{}, fmt.Errorf("doctor: run checks: %w", err)
	}

	return domain.DoctorResponse{
		Checks:    checks,
		AllPassed: allPassed,
	}, nil
}
