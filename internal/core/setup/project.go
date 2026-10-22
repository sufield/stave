package setup

import (
	"context"
	"fmt"
)

// DoctorCheckRunnerPort runs environment readiness checks.
type DoctorCheckRunnerPort interface {
	RunChecks(ctx context.Context, req DoctorRequest) (DoctorResponse, error)
}

// DoctorDeps groups the port interfaces for the doctor use case.
type DoctorDeps struct {
	Runner DoctorCheckRunnerPort
}

// Doctor runs environment readiness checks.
func Doctor(ctx context.Context, req DoctorRequest, deps DoctorDeps) (DoctorResponse, error) {
	if err := ctx.Err(); err != nil {
		return DoctorResponse{}, fmt.Errorf("doctor: %w", err)
	}

	resp, err := deps.Runner.RunChecks(ctx, req)
	if err != nil {
		return DoctorResponse{}, fmt.Errorf("doctor: %w", err)
	}

	return resp, nil
}
