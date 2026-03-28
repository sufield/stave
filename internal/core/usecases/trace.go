package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// TraceEvaluatorPort traces predicate evaluation for a control against an asset.
type TraceEvaluatorPort interface {
	TraceEvaluation(ctx context.Context, controlID, controlsDir, observationPath, assetID string) (any, error)
}

// TraceDeps groups the port interfaces for the trace use case.
type TraceDeps struct {
	Evaluator TraceEvaluatorPort
}

// Trace runs predicate evaluation tracing for a single control against a single asset.
func Trace(
	ctx context.Context,
	req domain.TraceRequest,
	deps TraceDeps,
) (domain.TraceResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.TraceResponse{}, fmt.Errorf("trace: %w", err)
	}

	if req.ControlID == "" {
		return domain.TraceResponse{}, fmt.Errorf("trace: control ID is required")
	}
	if req.AssetID == "" {
		return domain.TraceResponse{}, fmt.Errorf("trace: asset ID is required")
	}

	data, err := deps.Evaluator.TraceEvaluation(ctx, req.ControlID, req.ControlsDir, req.ObservationPath, req.AssetID)
	if err != nil {
		return domain.TraceResponse{}, fmt.Errorf("trace: %w", err)
	}

	return domain.TraceResponse{TraceData: data}, nil
}
