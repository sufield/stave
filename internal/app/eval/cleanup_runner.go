package eval

import "fmt"

// CleanupPlan summarizes shared cleanup execution state.
type CleanupPlan struct {
	CandidateCount int
	DryRun         bool
}

// CleanupDeps provides callbacks for snapshot cleanup commands (prune/archive).
type CleanupDeps struct {
	BuildPlan func() (CleanupPlan, error)
	Render    func(CleanupPlan) error
	Apply     func(CleanupPlan) error
}

// RunCleanup executes the common cleanup orchestration flow.
func RunCleanup(deps CleanupDeps) error {
	if deps.BuildPlan == nil || deps.Render == nil || deps.Apply == nil {
		return fmt.Errorf("cleanup dependencies are required")
	}
	plan, err := deps.BuildPlan()
	if err != nil {
		return fmt.Errorf("build cleanup plan: %w", err)
	}
	if err := deps.Render(plan); err != nil {
		return fmt.Errorf("render cleanup plan: %w", err)
	}
	if plan.CandidateCount == 0 || plan.DryRun {
		return nil
	}
	if err := deps.Apply(plan); err != nil {
		return fmt.Errorf("apply cleanup: %w", err)
	}
	return nil
}
