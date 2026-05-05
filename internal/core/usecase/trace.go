package usecase

import (
	"context"
	"errors"
	"fmt"
)

// --- Trace ---

// TraceRequest is the input for the trace use case.
type TraceRequest struct {
	ControlID       string `json:"control_id"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationPath string `json:"observation_path"`
	AssetID         string `json:"asset_id"`
}

// TraceResponse is the output of the trace use case.
type TraceResponse struct {
	TraceData any `json:"trace_data"`
}

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

	if deps.Evaluator == nil {
		return TraceResponse{}, errors.New("trace: deps.Evaluator is required")
	}
	if req.ControlID == "" {
		return TraceResponse{}, errors.New("trace: control ID is required")
	}
	if req.AssetID == "" {
		return TraceResponse{}, errors.New("trace: asset ID is required")
	}
	if req.ObservationPath == "" {
		return TraceResponse{}, errors.New("trace: observation path is required")
	}

	data, err := deps.Evaluator.TraceEvaluation(ctx, req.ControlID, req.ControlsDir, req.ObservationPath, req.AssetID)
	if err != nil {
		return TraceResponse{}, fmt.Errorf("trace: %w", err)
	}

	return TraceResponse{TraceData: data}, nil
}
