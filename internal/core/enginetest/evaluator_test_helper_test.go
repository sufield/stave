package enginetest

import (
	"time"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
)

// testDigester returns the default ports.Digester for domain tests.
// This is the single point of change if the algorithm is swapped.
func testDigester() ports.Digester { return crypto.NewHasher() }

// testIDGen returns the default ports.IdentityGenerator for domain tests.
func testIDGen() ports.IdentityGenerator { return crypto.NewHasher() }

// testCELEvaluator returns a CEL-based PredicateEval for domain tests.
func testCELEvaluator() policy.PredicateEval {
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
	r := engine.NewAssessor()
	r.Controls = controls
	r.SLAThreshold = maxUnsafe
	r.Clock = clock
	r.PredicateEval = testCELEvaluator()
	return &testEvaluator{runner: *r}
}

type testEvaluator struct {
	runner      engine.Assessor
	InputHashes *evaluation.InputHashes
}

func (e *testEvaluator) Controls() []policy.ControlDefinition {
	return e.runner.Controls
}

func (e *testEvaluator) Evaluate(snapshots []asset.Snapshot) evaluation.ComplianceReport {
	result, err := e.runner.Assess(snapshots, engine.AssessmentOptions{
		InputHashes: e.InputHashes,
	})
	if err != nil {
		panic("testEvaluator.Evaluate: " + err.Error())
	}
	return result
}
