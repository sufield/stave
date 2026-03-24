package domain

import (
	"time"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/engine"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// testDigester returns the default ports.Digester for domain tests.
// This is the single point of change if the algorithm is swapped.
func testDigester() ports.Digester { return crypto.NewHasher() }

// testIDGen returns the default ports.IdentityGenerator for domain tests.
func testIDGen() ports.IdentityGenerator { return crypto.NewHasher() }

// testCELEvaluator returns a CEL-based PredicateEval for domain tests.
func testCELEvaluator() engine.PredicateEvaluator {
	compiler, err := stavecel.NewCompiler()
	if err != nil {
		panic("testCELEvaluator: " + err.Error())
	}
	return func(ctl policy.ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (bool, error) {
		cp, err := compiler.Compile(ctl.UnsafePredicate)
		if err != nil {
			return false, err
		}
		return stavecel.Evaluate(cp, a, identities, ctl.Params.Raw())
	}
}

// NewEvaluator builds a test evaluator with optional InputHashes injection.
// It calls Prepare() on each control to mirror production loader behavior.
func NewEvaluator(controls []policy.ControlDefinition, maxUnsafe time.Duration, clock ports.Clock) *testEvaluator {
	for i := range controls {
		_ = controls[i].Prepare()
	}
	return &testEvaluator{
		runner: engine.Runner{
			Controls:          controls,
			MaxUnsafeDuration: maxUnsafe,
			Clock:             clock,
			CELEvaluator:      testCELEvaluator(),
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
