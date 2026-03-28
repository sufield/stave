package policy

import (
	"context"
	"fmt"
)

// FmtRunnerPort formats control and observation files.
type FmtRunnerPort interface {
	RunFmt(ctx context.Context, target string, checkOnly bool) (FmtResponse, error)
}

// FmtDeps groups the port interfaces for the fmt use case.
type FmtDeps struct {
	Runner FmtRunnerPort
}

// Fmt formats control/observation files or checks formatting.
func Fmt(ctx context.Context, req FmtRequest, deps FmtDeps) (FmtResponse, error) {
	if err := ctx.Err(); err != nil {
		return FmtResponse{}, fmt.Errorf("fmt: %w", err)
	}

	if req.Target == "" {
		return FmtResponse{}, fmt.Errorf("fmt: target path is required")
	}

	resp, err := deps.Runner.RunFmt(ctx, req.Target, req.CheckOnly)
	if err != nil {
		return FmtResponse{}, fmt.Errorf("fmt: %w", err)
	}
	return resp, nil
}
