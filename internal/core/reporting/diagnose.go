package reporting

import (
	"context"
	"fmt"
)

// DiagnoseRunnerPort runs diagnostic analysis.
type DiagnoseRunnerPort interface {
	RunDiagnosis(ctx context.Context, req DiagnoseRequest) (any, error)
}

// DiagnoseDetailPort runs single-finding detail analysis.
type DiagnoseDetailPort interface {
	RunDetail(ctx context.Context, controlsDir, observationsDir, controlID, assetID string) (any, error)
}

type DiagnoseDeps struct {
	Runner DiagnoseRunnerPort
	Detail DiagnoseDetailPort
}

// Diagnose runs diagnostic analysis, routing to detail mode when ControlID+AssetID are set.
func Diagnose(ctx context.Context, req DiagnoseRequest, deps DiagnoseDeps) (DiagnoseResponse, error) {
	if err := ctx.Err(); err != nil {
		return DiagnoseResponse{}, fmt.Errorf("diagnose: %w", err)
	}

	if req.ControlID != "" && req.AssetID != "" {
		data, err := deps.Detail.RunDetail(ctx, req.ControlsDir, req.ObservationsDir, req.ControlID, req.AssetID)
		if err != nil {
			return DiagnoseResponse{}, fmt.Errorf("diagnose: %w", err)
		}
		return DiagnoseResponse{ReportData: data, IsDetailMode: true}, nil
	}

	data, err := deps.Runner.RunDiagnosis(ctx, req)
	if err != nil {
		return DiagnoseResponse{}, fmt.Errorf("diagnose: %w", err)
	}
	return DiagnoseResponse{ReportData: data}, nil
}
