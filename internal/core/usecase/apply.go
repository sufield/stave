// Package usecase provides application-layer orchestration for stave commands
// including apply, fix, gate, verify, and trace operations.
package usecase

import (
	"context"
	"fmt"
)

// --- Apply ---

// ApplyRequest is the input for the apply use case.
type ApplyRequest struct {
	ControlsDir        string   `json:"controls_dir,omitempty"`
	ObservationsDir    string   `json:"observations_dir,omitempty"`
	MaxUnsafeDuration  string   `json:"max_unsafe_duration,omitempty"`
	NowTime            string   `json:"now_time,omitempty"`
	Format             string   `json:"format,omitempty"`
	DryRun             bool     `json:"dry_run,omitempty"`
	AllowUnknownInput  bool     `json:"allow_unknown_input,omitempty"`
	ExemptionFile      string   `json:"exemption_file,omitempty"`
	IntegrityManifest  string   `json:"integrity_manifest,omitempty"`
	IntegrityPublicKey string   `json:"integrity_public_key,omitempty"`
	Profile            string   `json:"profile,omitempty"`
	InputFile          string   `json:"input_file,omitempty"`
	BucketAllowlist    []string `json:"bucket_allowlist,omitempty"`
	IncludeAll         bool     `json:"include_all,omitempty"`
}

// ApplyResponse is the output of the apply use case.
type ApplyResponse struct {
	EvaluationData any      `json:"evaluation_data"`
	HasViolations  bool     `json:"has_violations"`
	Warnings       []string `json:"warnings,omitempty"`
}

// EvaluationRunnerPort runs control evaluation against observations.
type EvaluationRunnerPort interface {
	RunEvaluation(ctx context.Context, req ApplyRequest) (ApplyResponse, error)
}

// ApplyDeps groups the port interfaces for the apply use case.
type ApplyDeps struct {
	Runner EvaluationRunnerPort
}

// Apply runs control evaluation after validating inputs.
func Apply(ctx context.Context, req ApplyRequest, deps ApplyDeps) (ApplyResponse, error) {
	if err := ctx.Err(); err != nil {
		return ApplyResponse{}, fmt.Errorf("apply: %w", err)
	}

	if req.Profile != "" && req.InputFile == "" {
		return ApplyResponse{}, fmt.Errorf("apply: --input is required when using --profile")
	}

	resp, err := deps.Runner.RunEvaluation(ctx, req)
	if err != nil {
		return ApplyResponse{}, fmt.Errorf("apply: %w", err)
	}

	return resp, nil
}
