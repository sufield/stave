package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// LintRunnerPort lints control files in a path and returns diagnostics.
type LintRunnerPort interface {
	LintPath(ctx context.Context, target string) ([]domain.LintDiagnostic, int, error)
}

// LintDeps groups the port interfaces for the lint use case.
type LintDeps struct {
	Runner LintRunnerPort
}

// Lint lints control files and returns diagnostics.
func Lint(
	ctx context.Context,
	req domain.LintRequest,
	deps LintDeps,
) (domain.LintResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.LintResponse{}, fmt.Errorf("lint: %w", err)
	}

	if req.Target == "" {
		return domain.LintResponse{}, fmt.Errorf("lint: target path is required")
	}

	diags, errorCount, err := deps.Runner.LintPath(ctx, req.Target)
	if err != nil {
		return domain.LintResponse{}, fmt.Errorf("lint: %w", err)
	}

	return domain.LintResponse{
		Diagnostics: diags,
		ErrorCount:  errorCount,
	}, nil
}
