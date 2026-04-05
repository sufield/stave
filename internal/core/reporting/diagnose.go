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

// DiagnoseDeps represents a diagnosedeps value.
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

// --- Diagnose Types ---

// DiagnoseRequest represents a diagnoserequest value.
type DiagnoseRequest struct {
	ControlsDir       string   `json:"controls_dir,omitempty"`
	ObservationsDir   string   `json:"observations_dir,omitempty"`
	PreviousOutput    string   `json:"previous_output,omitempty"`
	MaxUnsafeDuration string   `json:"max_unsafe_duration,omitempty"`
	Now               string   `json:"now,omitempty"`
	CaseFilter        []string `json:"case_filter,omitempty"`
	SignalContains    string   `json:"signal_contains,omitempty"`
	ControlID         string   `json:"control_id,omitempty"`
	AssetID           string   `json:"asset_id,omitempty"`
}

// DiagnoseResponse represents a diagnoseresponse value.
type DiagnoseResponse struct {
	ReportData   any  `json:"report_data"`
	IsDetailMode bool `json:"is_detail_mode,omitempty"`
}
