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

// StatusScannerPort scans project state and recommends a next action.
type StatusScannerPort interface {
	ScanStatus(ctx context.Context, req StatusRequest) (StatusResponse, error)
}

// StatusDeps groups the port interfaces for the status use case.
type StatusDeps struct {
	Scanner StatusScannerPort
}

// Status checks project status and returns the recommended next command.
func Status(ctx context.Context, req StatusRequest, deps StatusDeps) (StatusResponse, error) {
	if err := ctx.Err(); err != nil {
		return StatusResponse{}, fmt.Errorf("status: %w", err)
	}

	resp, err := deps.Scanner.ScanStatus(ctx, req)
	if err != nil {
		return StatusResponse{}, fmt.Errorf("status: %w", err)
	}

	return resp, nil
}

// ProjectScaffolderPort creates or previews a Stave project scaffold.
type ProjectScaffolderPort interface {
	ScaffoldProject(ctx context.Context, req InitRequest) (InitResponse, error)
}

// InitDeps groups the port interfaces for the init use case.
type InitDeps struct {
	Scaffolder ProjectScaffolderPort
}

// Init initializes a starter Stave project structure.
func Init(ctx context.Context, req InitRequest, deps InitDeps) (InitResponse, error) {
	if err := ctx.Err(); err != nil {
		return InitResponse{}, fmt.Errorf("init-project: %w", err)
	}

	if req.Dir == "" {
		return InitResponse{}, fmt.Errorf("init-project: directory is required")
	}

	if req.Profile != "" && req.Profile != "aws-s3" {
		return InitResponse{}, fmt.Errorf("init-project: unsupported profile %q (supported: aws-s3)", req.Profile)
	}

	if req.CaptureCadence != "" && req.CaptureCadence != "daily" && req.CaptureCadence != "hourly" {
		return InitResponse{}, fmt.Errorf("init-project: unsupported capture-cadence %q (supported: daily, hourly)", req.CaptureCadence)
	}

	resp, err := deps.Scaffolder.ScaffoldProject(ctx, req)
	if err != nil {
		return InitResponse{}, fmt.Errorf("init-project: %w", err)
	}

	return resp, nil
}
