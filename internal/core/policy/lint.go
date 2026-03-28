package policy

import (
	"context"
	"fmt"
)

// LintRunnerPort lints control files for style and correctness issues.
type LintRunnerPort interface {
	RunLint(ctx context.Context, target string) (LintResponse, error)
}

// LintDeps groups the port interfaces for the lint use case.
type LintDeps struct {
	Runner LintRunnerPort
}

// Lint runs linting on control files and returns diagnostics.
func Lint(ctx context.Context, req LintRequest, deps LintDeps) (LintResponse, error) {
	if err := ctx.Err(); err != nil {
		return LintResponse{}, fmt.Errorf("lint: %w", err)
	}

	if req.Target == "" {
		return LintResponse{}, fmt.Errorf("lint: target path is required")
	}

	resp, err := deps.Runner.RunLint(ctx, req.Target)
	if err != nil {
		return LintResponse{}, fmt.Errorf("lint: %w", err)
	}
	return resp, nil
}
