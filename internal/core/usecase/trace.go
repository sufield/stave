package usecase

import (
	"context"
	"fmt"
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
func Trace(ctx context.Context, req TraceRequest, deps TraceDeps) (TraceResponse, error) {
	if err := ctx.Err(); err != nil {
		return TraceResponse{}, fmt.Errorf("trace: %w", err)
	}

	if req.ControlID == "" {
		return TraceResponse{}, fmt.Errorf("trace: control ID is required")
	}
	if req.AssetID == "" {
		return TraceResponse{}, fmt.Errorf("trace: asset ID is required")
	}

	data, err := deps.Evaluator.TraceEvaluation(ctx, req.ControlID, req.ControlsDir, req.ObservationPath, req.AssetID)
	if err != nil {
		return TraceResponse{}, fmt.Errorf("trace: %w", err)
	}

	return TraceResponse{TraceData: data}, nil
}
