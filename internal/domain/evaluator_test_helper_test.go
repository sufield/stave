package domain

import (
	"time"

	"github.com/sufield/stave/internal/domain/policy"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/engine"
	"github.com/sufield/stave/internal/domain/ports"
)

// NewEvaluator builds a test evaluator with optional InputHashes injection.
// It calls Prepare() on each control to mirror production loader behavior.
func NewEvaluator(controls []policy.ControlDefinition, maxUnsafe time.Duration, clock ports.Clock) *testEvaluator {
	for i := range controls {
		_ = controls[i].Prepare()
	}
	return &testEvaluator{
		runner: engine.Runner{
			Controls:  controls,
			MaxUnsafe: maxUnsafe,
			Clock:     clock,
		},
	}
}

type testEvaluator struct {
	runner      engine.Runner
	InputHashes *evaluation.InputHashes
}

func (e *testEvaluator) Controls() []policy.ControlDefinition {
	return e.runner.Controls
}

func (e *testEvaluator) Evaluate(snapshots []asset.Snapshot) evaluation.Result {
	e.runner.InputHashes = e.InputHashes
	result, err := e.runner.Evaluate(snapshots)
	if err != nil {
		panic("testEvaluator.Evaluate: " + err.Error())
	}
	return result
}
