package usecase

import (
	"context"
	"fmt"
)

// FindingLoaderPort loads a finding by its selector from an evaluation file.
type FindingLoaderPort interface {
	LoadFindingWithPlan(ctx context.Context, inputPath, findingRef string) (any, error)
}

// Deps groups the port interfaces for the fix use case.
type FixDeps struct {
	Loader FindingLoaderPort
}

// Fix loads an evaluation artifact and returns remediation guidance for a single finding.
func Fix(ctx context.Context, req FixRequest, deps FixDeps) (FixResponse, error) {
	if err := ctx.Err(); err != nil {
		return FixResponse{}, fmt.Errorf("fix: %w", err)
	}

	if req.FindingRef == "" {
		return FixResponse{}, fmt.Errorf("fix: finding selector cannot be empty")
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

// FixLoop runs the full remediation verification lifecycle.
func FixLoop(ctx context.Context, req FixLoopRequest, deps LoopDeps) (FixLoopResponse, error) {
	if err := ctx.Err(); err != nil {
		return FixLoopResponse{}, fmt.Errorf("fix-loop: %w", err)
	}

	if req.BeforeDir == "" {
		return FixLoopResponse{}, fmt.Errorf("fix-loop: before observations directory is required")
	}
	if req.AfterDir == "" {
		return FixLoopResponse{}, fmt.Errorf("fix-loop: after observations directory is required")
	}

	resp, err := deps.Runner.RunFixLoop(ctx, req)
	if err != nil {
		return FixLoopResponse{}, fmt.Errorf("fix-loop: %w", err)
	}

	return resp, nil
}
