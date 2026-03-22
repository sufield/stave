package eval

import (
	"context"
	"fmt"
)

// CleanupPlan summarizes shared cleanup execution state.
type CleanupPlan struct {
	CandidateCount int
	DryRun         bool
}

// CleanupOrchestrator defines the three-phase contract for snapshot cleanup
// commands (prune, archive). Implementations provide the concrete plan
// building, rendering, and application logic.
type CleanupOrchestrator interface {
	BuildPlan(ctx context.Context) (CleanupPlan, error)
	Render(ctx context.Context, plan CleanupPlan) error
	Apply(ctx context.Context, plan CleanupPlan) error
}

// RunCleanup executes the common cleanup orchestration flow:
// BuildPlan → Apply (if not dry-run) → Render.
// Apply runs before Render so the rendered output accurately reflects
// whether the mutation succeeded (the "Applied" field is truthful).
func RunCleanup(ctx context.Context, orch CleanupOrchestrator) error {
	plan, err := orch.BuildPlan(ctx)
	if err != nil {
		return fmt.Errorf("build cleanup plan: %w", err)
	}
	if plan.CandidateCount > 0 && !plan.DryRun {
		if err := orch.Apply(ctx, plan); err != nil {
			return fmt.Errorf("apply cleanup: %w", err)
		}
	}
	if err := orch.Render(ctx, plan); err != nil {
		return fmt.Errorf("render cleanup plan: %w", err)
	}
	return nil
}
