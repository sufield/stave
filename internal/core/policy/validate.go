package policy

import (
	"context"
	"fmt"
)

// ValidateRunnerPort validates controls and observations and returns diagnostics.
type ValidateRunnerPort interface {
	Validate(ctx context.Context, controlsDir, observationsDir string) (ValidateResponse, error)
}

// ValidateSingleFilePort validates a single input file.
type ValidateSingleFilePort interface {
	ValidateFile(ctx context.Context, inputFile, kind string) (ValidateResponse, error)
}

// ValidateDeps groups the port interfaces for the validate use case.
type ValidateDeps struct {
	ProjectValidator ValidateRunnerPort
	FileValidator    ValidateSingleFilePort
}

// Validate runs input validation and returns diagnostics.
func Validate(ctx context.Context, req ValidateRequest, deps ValidateDeps) (ValidateResponse, error) {
	if err := ctx.Err(); err != nil {
		return ValidateResponse{}, fmt.Errorf("validate: %w", err)
	}

	if req.InputFile != "" {
		if deps.FileValidator == nil {
			return ValidateResponse{}, fmt.Errorf("validate: single-file validation not available")
		}
		resp, err := deps.FileValidator.ValidateFile(ctx, req.InputFile, req.Kind)
		if err != nil {
			return ValidateResponse{}, fmt.Errorf("validate: file %s: %w", req.InputFile, err)
		}
		return resp, nil
	}

	if deps.ProjectValidator == nil {
		return ValidateResponse{}, fmt.Errorf("validate: project validation not available")
	}
	resp, err := deps.ProjectValidator.Validate(ctx, req.ControlsDir, req.ObservationsDir)
	if err != nil {
		return ValidateResponse{}, fmt.Errorf("validate: %w", err)
	}
	return resp, nil
}
