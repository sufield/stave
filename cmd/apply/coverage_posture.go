package apply

import (
	"log/slog"

	covadapter "github.com/sufield/stave/internal/adapters/coverage"
	appeval "github.com/sufield/stave/internal/app/eval"
	policy "github.com/sufield/stave/internal/core/controldef"
	corecov "github.com/sufield/stave/internal/core/evaluation/coverage"
)

// activeControls returns the controls used by the most recent assessment.
// Prefers the runner's recorded LoadedControls (populated for both
// project-config-preloaded and runtime-loaded paths) over the static
// ActivePolicies on Config (which is empty when controls are loaded
// from disk inside the workflow).
func activeControls(deps *appeval.ApplyDeps) []policy.ControlDefinition {
	if deps == nil || deps.Runner == nil {
		return nil
	}
	if loaded := deps.Runner.LoadedControls; len(loaded) > 0 {
		return loaded
	}
	return deps.Config.ActivePolicies
}

// buildCoveragePosture loads the embedded alternative-tool inventories
// and aggregates them with the active controls into a CoverageIndex.
// Returns nil when no inventories or controls are available; that
// signals "no coverage posture to report" to the output pipeline.
//
// Inventory load errors are logged and treated as absence rather than
// fatal — coverage posture is decorative metadata, not load-bearing
// for evaluation correctness.
func buildCoveragePosture(controls []policy.ControlDefinition, logger *slog.Logger) *corecov.CoverageIndex {
	if len(controls) == 0 {
		return nil
	}
	inventories, err := covadapter.LoadEmbedded()
	if err != nil {
		if logger != nil {
			logger.Warn("coverage posture disabled: inventory load failed", "error", err)
		}
		return nil
	}
	idx := corecov.BuildCoverageIndex(controls, inventories)
	if len(idx.ByTool) == 0 {
		return nil
	}
	return &idx
}
