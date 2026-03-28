package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ExplainControlFinderPort finds and analyzes a control by its ID.
type ExplainControlFinderPort interface {
	ExplainControl(ctx context.Context, controlsDir, controlID string) (domain.ExplainResponse, error)
}

// ExplainDeps groups the port interfaces for the explain use case.
type ExplainDeps struct {
	Finder ExplainControlFinderPort
}

// Explain analyzes a control's predicate rules and returns a breakdown.
func Explain(
	ctx context.Context,
	req domain.ExplainRequest,
	deps ExplainDeps,
) (domain.ExplainResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.ExplainResponse{}, fmt.Errorf("explain: %w", err)
	}

	if req.ControlID == "" {
		return domain.ExplainResponse{}, fmt.Errorf("explain: control ID is required")
	}

	resp, err := deps.Finder.ExplainControl(ctx, req.ControlsDir, req.ControlID)
	if err != nil {
		return domain.ExplainResponse{}, fmt.Errorf("explain: %w", err)
	}

	return resp, nil
}
