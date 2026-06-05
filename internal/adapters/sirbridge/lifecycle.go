package sirbridge

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/kernel"
)

// EngineLifecycleSource implements sir.LifecycleSource by
// delegating to the engine's canonical
// BuildLifecyclesPerControl. The CEL evaluator is injected at
// construction time — the SIR core forbids importing celeval
// directly, so the caller (the export-sir CLI, future
// integration tests) constructs the evaluator and hands it in.
//
// Returning the engine's map directly preserves the lifecycle
// invariants (sorted history, sticky clamped flag, active-window
// state) the SIR builder reads in exposureWindowsFromLifecycles.
// No translation happens here.
type EngineLifecycleSource struct {
	predicateEval controldef.PredicateEval
}

// NewEngineLifecycleSource returns a lifecycle source that
// delegates to engine.BuildLifecyclesPerControl using the
// supplied predicate evaluator. The evaluator must be the same
// one the assessor would use; mismatched evaluators would make
// the SIR's Temporal.Windows disagree with the assessor's
// findings, breaking differential-test parity in Iter 4.
func NewEngineLifecycleSource(eval controldef.PredicateEval) *EngineLifecycleSource {
	return &EngineLifecycleSource{predicateEval: eval}
}

// Lifecycles satisfies sir.LifecycleSource.
func (s *EngineLifecycleSource) Lifecycles(controls []controldef.ControlDefinition, snapshots []asset.Snapshot) (map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, error) {
	// context.Background(): the sir.LifecycleSource interface (and
	// sir.Builder.Build above it) does not yet carry a ctx, so caller
	// cancellation cannot reach this SIR path. Wiring ctx through the SIR
	// builder chain is a separate change; the interruptibility bug this
	// fixes is on the assessor's Assess path, which passes its real ctx.
	lc, err := engine.BuildLifecyclesPerControl(context.Background(), controls, snapshots, s.predicateEval)
	if err != nil {
		return nil, fmt.Errorf("build lifecycles: %w", err)
	}
	return lc, nil
}
