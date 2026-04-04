package eval

import (
	"context"
	"fmt"
)

// VerificationRunnerPort compares before/after evaluations to check remediation.
type VerificationRunnerPort interface {
	RunVerification(ctx context.Context, req Request) (VerifyResponse, error)
}

// Deps groups the port interfaces for the verify use case.
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
