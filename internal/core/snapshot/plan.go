package snapshot

import (
	"context"
	"fmt"
)

// RetentionPlannerPort previews or executes multi-tier snapshot retention.
type RetentionPlannerPort interface {
	PlanRetention(ctx context.Context, req PlanRequest) (PlanResponse, error)
}

// PlanDeps groups the port interfaces for the snapshot-plan use case.
type PlanDeps struct {
	Planner RetentionPlannerPort
}

// Plan previews or executes multi-tier snapshot retention across directories.
func Plan(
	ctx context.Context,
	req PlanRequest,
	deps PlanDeps,
) (PlanResponse, error) {
	if err := ctx.Err(); err != nil {
		return PlanResponse{}, fmt.Errorf("snapshot-plan: %w", err)
	}

	if req.ObservationsRoot == "" {
		return PlanResponse{}, fmt.Errorf("snapshot-plan: observations root is required")
	}

	resp, err := deps.Planner.PlanRetention(ctx, req)
	if err != nil {
		return PlanResponse{}, fmt.Errorf("snapshot-plan: %w", err)
	}

	return resp, nil
}
