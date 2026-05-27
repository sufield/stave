package engine

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
)

// TestLargeScale_WallClock prints a single-shot wall-clock measurement
// of Assess() against 2000 controls × 200 assets. Gated behind
// STAVE_PERF=1 so it does not slow normal test runs.
//
//	STAVE_PERF=1 GOMAXPROCS=1 go test -run TestLargeScale_WallClock -v ./internal/core/evaluation/engine/
//	STAVE_PERF=1 GOMAXPROCS=8 go test -run TestLargeScale_WallClock -v ./internal/core/evaluation/engine/
//
// The ratio between the two runs is the apples-to-apples
// parallelism speedup against the same fixture on the same machine.
func TestLargeScale_WallClock(t *testing.T) {
	if os.Getenv("STAVE_PERF") == "" {
		t.Skip("set STAVE_PERF=1 to run wall-clock measurement")
	}
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	const controlCount = 2_000
	controls := make([]policy.ControlDefinition, controlCount)
	for i := range controlCount {
		controls[i] = policy.ControlDefinition{
			ID:   kernel.ControlID(fmt.Sprintf("CTL.WALL.%04d", i)),
			Name: fmt.Sprintf("wall-%d", i),
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		}
		if err := controls[i].Prepare(); err != nil {
			t.Fatalf("prepare control %d: %v", i, err)
		}
	}
	snapshots := buildBenchmarkSnapshots(now, 200)
	assessor := &Assessor{
		controls:     controls,
		slaThreshold: 168 * time.Hour,
		clock:        ports.FixedClock(now),
		// Wire a real predicate evaluator so Assess() actually evaluates
		// each control×asset pair — the lambda below mirrors the
		// "alwaysUnsafe" helper in testbuilder_test.go and is what makes
		// the per-control work visible to the timer. Without this, the
		// precondition check at the top of Assess() returns immediately
		// and the benchmark measures the error-return cost, not the
		// evaluation path.
		predicateEval: func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return true, nil
		},
		predicateParser: func(_ any) (*policy.UnsafePredicate, error) {
			return &policy.UnsafePredicate{}, nil
		},
	}
	// Warm-up run (CEL JIT, runtime maps, etc.).
	_, _ = assessor.Assess(context.Background(), snapshots)

	// Three timed runs — report each + the min.
	var minDur time.Duration
	for i := range 3 {
		start := time.Now()
		report, err := assessor.Assess(context.Background(), snapshots)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("assess run %d: %v", i, err)
		}
		if i == 0 || elapsed < minDur {
			minDur = elapsed
		}
		t.Logf("run %d: %v (GOMAXPROCS=%d controls=%d assets/snapshot=%d findings=%d checks=%d)",
			i, elapsed, runtime.GOMAXPROCS(0), controlCount, 200, len(report.Findings), len(report.Checks))
	}
	t.Logf("BEST: %v", minDur)
}
