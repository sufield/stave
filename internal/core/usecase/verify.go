package usecase

import (
	"context"
	"fmt"
)

// --- Verify ---

// Request is the input for the verify use case.
type Request struct {
	BeforeDir         string `json:"before_dir"`
	AfterDir          string `json:"after_dir"`
	ControlsDir       string `json:"controls_dir,omitempty"`
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`
	NowTime           string `json:"now_time,omitempty"`
	AllowUnknownInput bool   `json:"allow_unknown_input,omitempty"`
}

// VerifyResponse is the output of the verify use case.
type VerifyResponse struct {
	VerificationData any  `json:"verification_data"`
	HasRemaining     bool `json:"has_remaining"`
	HasIntroduced    bool `json:"has_introduced"`
}

// VerificationRunnerPort compares before/after evaluations to check remediation.
type VerificationRunnerPort interface {
	RunVerification(ctx context.Context, req Request) (VerifyResponse, error)
}

// VerifyDeps groups the port interfaces for the verify use case.
type VerifyDeps struct {
	Runner VerificationRunnerPort
}

// Verify compares before/after evaluations to check whether remediation resolved findings.
func Verify(ctx context.Context, req Request, deps VerifyDeps) (VerifyResponse, error) {
	if err := ctx.Err(); err != nil {
		return VerifyResponse{}, fmt.Errorf("verify: %w", err)
	}

	if req.BeforeDir == "" {
		return VerifyResponse{}, fmt.Errorf("verify: before observations directory is required")
	}
	if req.AfterDir == "" {
		return VerifyResponse{}, fmt.Errorf("verify: after observations directory is required")
	}

	resp, err := deps.Runner.RunVerification(ctx, req)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("verify: %w", err)
	}

	return resp, nil
}
