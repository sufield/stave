package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// FmtRunnerPort formats files at a target path.
type FmtRunnerPort interface {
	FormatPath(ctx context.Context, target string, checkOnly bool) (processed, changed int, err error)
}

// FmtDeps groups the port interfaces for the fmt use case.
type FmtDeps struct {
	Runner FmtRunnerPort
}

// Fmt formats control and observation files deterministically.
func Fmt(
	ctx context.Context,
	req domain.FmtRequest,
	deps FmtDeps,
) (domain.FmtResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.FmtResponse{}, fmt.Errorf("fmt: %w", err)
	}

	if req.Target == "" {
		return domain.FmtResponse{}, fmt.Errorf("fmt: target path is required")
	}

	processed, changed, err := deps.Runner.FormatPath(ctx, req.Target, req.CheckOnly)
	if err != nil {
		return domain.FmtResponse{}, fmt.Errorf("fmt: %w", err)
	}

	return domain.FmtResponse{
		FilesProcessed: processed,
		FilesChanged:   changed,
	}, nil
}
