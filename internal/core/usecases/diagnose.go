package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// DiagnoseRunnerPort runs diagnostic analysis on evaluation inputs.
type DiagnoseRunnerPort interface {
	RunDiagnosis(ctx context.Context, req domain.DiagnoseRequest) (any, error)
}

// DiagnoseDetailPort runs single-finding detail analysis.
type DiagnoseDetailPort interface {
	RunDetail(ctx context.Context, controlsDir, observationsDir, controlID, assetID string) (any, error)
}

// DiagnoseDeps groups the port interfaces for the diagnose use case.
type DiagnoseDeps struct {
	Runner       DiagnoseRunnerPort
	DetailRunner DiagnoseDetailPort
}

// Diagnose runs diagnostic analysis and returns the results.
func Diagnose(
	ctx context.Context,
	req domain.DiagnoseRequest,
	deps DiagnoseDeps,
) (domain.DiagnoseResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.DiagnoseResponse{}, fmt.Errorf("diagnose: %w", err)
	}

	// Detail mode: both control-id and asset-id specified
	if req.ControlID != "" && req.AssetID != "" {
		if deps.DetailRunner == nil {
			return domain.DiagnoseResponse{}, fmt.Errorf("diagnose: detail mode not available")
		}
		data, err := deps.DetailRunner.RunDetail(ctx, req.ControlsDir, req.ObservationsDir, req.ControlID, req.AssetID)
		if err != nil {
			return domain.DiagnoseResponse{}, fmt.Errorf("diagnose: detail: %w", err)
		}
		return domain.DiagnoseResponse{ReportData: data, IsDetailMode: true}, nil
	}

	// Standard mode
	data, err := deps.Runner.RunDiagnosis(ctx, req)
	if err != nil {
		return domain.DiagnoseResponse{}, fmt.Errorf("diagnose: %w", err)
	}
	return domain.DiagnoseResponse{ReportData: data}, nil
}
