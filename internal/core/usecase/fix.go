package usecase

import (
	"context"
	"errors"
	"fmt"
)

// --- Fix ---

// FixRequest is the input for the fix use case.
type FixRequest struct {
	InputPath  string `json:"input_path"`
	FindingRef string `json:"finding_ref"`
}

// FixResponse is the output of the fix use case.
type FixResponse struct {
	Data any `json:"data"`
}

// FindingLoaderPort loads a finding by its selector from an evaluation file.
type FindingLoaderPort interface {
	LoadFindingWithPlan(ctx context.Context, inputPath, findingRef string) (any, error)
}

// FixDeps groups the port interfaces for the fix use case.
type FixDeps struct {
	Loader FindingLoaderPort
}

// Fix loads an evaluation artifact and returns remediation guidance for a single finding.
func Fix(ctx context.Context, req FixRequest, deps FixDeps) (FixResponse, error) {
	if err := ctx.Err(); err != nil {
		return FixResponse{}, fmt.Errorf("fix: %w", err)
	}

	if deps.Loader == nil {
		return FixResponse{}, errors.New("fix: deps.Loader is required")
	}
	if req.InputPath == "" {
		return FixResponse{}, errors.New("fix: input path cannot be empty")
	}
	if req.FindingRef == "" {
		return FixResponse{}, errors.New("fix: finding selector cannot be empty")
	}

	data, err := deps.Loader.LoadFindingWithPlan(ctx, req.InputPath, req.FindingRef)
	if err != nil {
		return FixResponse{}, fmt.Errorf("fix: %w", err)
	}

	return FixResponse{Data: data}, nil
}

// FixLoopRunnerPort runs the apply-before/apply-after/verify workflow.
type FixLoopRunnerPort interface {
	RunFixLoop(ctx context.Context, req FixLoopRequest) (FixLoopResponse, error)
}

// LoopDeps groups the port interfaces for the fix-loop use case.
type LoopDeps struct {
	Runner FixLoopRunnerPort
}

// --- Fix Loop ---

// FixLoopRequest is the input for the fix-loop use case.
type FixLoopRequest struct {
	BeforeDir         string `json:"before_dir"`
	AfterDir          string `json:"after_dir"`
	ControlsDir       string `json:"controls_dir,omitempty"`
	OutDir            string `json:"out_dir,omitempty"`
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`
	EvalTimeRaw       string `json:"eval_time,omitempty"`
}

// FixLoopResponse is the output of the fix-loop use case.
type FixLoopResponse struct {
	ReportData    any  `json:"report_data"`
	HasViolations bool `json:"has_violations"`
}

// FixLoop runs the full remediation verification lifecycle.
func FixLoop(ctx context.Context, req FixLoopRequest, deps LoopDeps) (FixLoopResponse, error) {
	if err := ctx.Err(); err != nil {
		return FixLoopResponse{}, fmt.Errorf("fix-loop: %w", err)
	}

	if deps.Runner == nil {
		return FixLoopResponse{}, errors.New("fix-loop: deps.Runner is required")
	}
	if req.BeforeDir == "" {
		return FixLoopResponse{}, errors.New("fix-loop: before observations directory is required")
	}
	if req.AfterDir == "" {
		return FixLoopResponse{}, errors.New("fix-loop: after observations directory is required")
	}

	resp, err := deps.Runner.RunFixLoop(ctx, req)
	if err != nil {
		return FixLoopResponse{}, fmt.Errorf("fix-loop: %w", err)
	}

	return resp, nil
}
