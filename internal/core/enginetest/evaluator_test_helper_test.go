package enginetest

import (
	"context"
	"fmt"
	"sync"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
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

// sharedCompiler is constructed once for the test package and reused
// across every NewEvaluator call. The earlier shape built a fresh
// compiler per evaluator, so identical predicates were re-compiled
// for every test in the package — the package-level Compile cache
// only helps when the SAME compiler instance sees the same
// expression twice. Compiler is read-only-after-init and
// goroutine-safe (its internal cache uses RWMutex), so a shared
// instance is safe even for parallel test runs.
var (
	sharedCompiler     *stavecel.Compiler
	sharedCompilerOnce sync.Once
	errSharedCompiler  error
)

func getSharedCompiler() (*stavecel.Compiler, error) {
	sharedCompilerOnce.Do(func() {
		sharedCompiler, errSharedCompiler = stavecel.NewCompiler()
	})
	if errSharedCompiler != nil {
		return nil, fmt.Errorf("create CEL compiler: %w", errSharedCompiler)
	}
	return sharedCompiler, nil
}

// testCELEvaluator returns a CEL-based PredicateEval for domain tests.
func testCELEvaluator() policy.PredicateEval {
	compiler, err := getSharedCompiler()
	if err != nil {
		panic("testCELEvaluator: " + err.Error())
	}
	return func(ctl policy.ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (bool, error) {
		cp, err := compiler.Compile(ctl.UnsafePredicate)
		if err != nil {
			return false, fmt.Errorf("compile: %w", err)
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
	r := engine.NewAssessor(
		engine.WithControls(controls),
		engine.WithSLAThreshold(maxUnsafe),
		engine.WithClock(clock),
		engine.WithPredicateEval(testCELEvaluator()),
		engine.WithPredicateParser(func(_ any) (*policy.UnsafePredicate, error) {
			return &policy.UnsafePredicate{}, nil
		}),
	)
	return &testEvaluator{runner: *r}
}

type testEvaluator struct {
	runner      engine.Assessor
	InputHashes *evaluation.InputHashes
}

func (e *testEvaluator) Controls() []policy.ControlDefinition {
	return e.runner.Controls()
}

func (e *testEvaluator) Evaluate(snapshots []asset.Snapshot) evaluation.ComplianceReport {
	result, err := e.runner.Assess(context.Background(), snapshots, engine.AssessmentOptions{
		InputHashes: e.InputHashes,
	})
	if err != nil {
		panic("testEvaluator.Evaluate: " + err.Error())
	}
	return result
}
