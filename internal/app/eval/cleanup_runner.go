package eval

import "fmt"

// CleanupPlan summarizes shared cleanup execution state.
type CleanupPlan struct {
	CandidateCount int
	DryRun         bool
}

// CleanupOrchestrator defines the three-phase contract for snapshot cleanup
// commands (prune, archive). Implementations provide the concrete plan
// building, rendering, and application logic.
type CleanupOrchestrator interface {
	BuildPlan() (CleanupPlan, error)
	Render(CleanupPlan) error
	Apply(CleanupPlan) error
}

// RunCleanup executes the common cleanup orchestration flow:
// BuildPlan → Render → (optionally) Apply.
func RunCleanup(orch CleanupOrchestrator) error {
	plan, err := orch.BuildPlan()
	if err != nil {
		return fmt.Errorf("build cleanup plan: %w", err)
	}
	if err := orch.Render(plan); err != nil {
		return fmt.Errorf("render cleanup plan: %w", err)
	}
	if plan.CandidateCount == 0 || plan.DryRun {
		return nil
	}
	if err := orch.Apply(plan); err != nil {
		return fmt.Errorf("apply cleanup: %w", err)
	}
	return nil
}
