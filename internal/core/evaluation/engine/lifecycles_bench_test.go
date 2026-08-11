package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// slowPredicateEval simulates the real per-call cost of a CEL
// predicate (compile cache hot, but parse-tree walk and program
// execution still take microseconds). The earlier benchmarks used
// benchPredicateEval which returns true in nanoseconds — that
// understates the real CPU profile and made BuildLifecyclesPerControl
// look like a cheap loop when it is actually the dominant hot
// path at production scale (2,662 controls × thousands of assets).
//
// 30µs is calibrated from a representative S3 control predicate
// running through cel-go's interpreter on cached AST + program.
// The exact value is less important than that it's non-trivial:
// the parallelisation win is invisible when the inner call is
// ~10ns because the loop is memory-bound, not compute-bound.
func slowPredicateEval(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
	deadline := time.Now().Add(30 * time.Microsecond)
	x := 0
	for time.Now().Before(deadline) {
		x++ // busy-wait CPU work so a real CPU core is occupied
	}
	_ = x
	return true, nil
}

// buildSyntheticInputs constructs the (controls, snapshots) pair used
// by the lifecycle benchmark. Each asset is in every control's
// vendor scope (vendor=AWS), so the per-vendor index returns the
// full control list — the work per asset is proportional to the
// catalog size, matching the production hot path.
func buildSyntheticInputs(numControls, numAssets, numSnapshots int) ([]policy.ControlDefinition, []asset.Snapshot) {
	controls := make([]policy.ControlDefinition, 0, numControls)
	for i := range numControls {
		controls = append(controls, policy.ControlDefinition{
			ID:        kernel.ControlID(fmt.Sprintf("CTL.BENCH.%05d", i)),
			Name:      fmt.Sprintf("bench-%05d", i),
			Type:      policy.TypeUnsafeState,
			ScopeTags: []kernel.ScopeTag{"aws"},
		})
	}
	snapshots := make([]asset.Snapshot, 0, numSnapshots)
	for s := range numSnapshots {
		assets := make([]asset.Asset, 0, numAssets)
		captured := time.Date(2026, 1, 1+s, 0, 0, 0, 0, time.UTC)
		for i := range numAssets {
			assets = append(assets, asset.Asset{
				ID:     asset.ID(fmt.Sprintf("asset-%05d", i)),
				Type:   "aws_s3_bucket",
				Vendor: "aws",
			})
		}
		snapshots = append(snapshots, asset.Snapshot{
			CapturedAt: captured,
			Assets:     assets,
		})
	}
	return controls, snapshots
}

// BenchmarkBuildLifecyclesPerControl measures the parallel
// per-asset fan-out under realistic CEL cost. The scale is
// representative of mid-sized production (100 controls ×
// 200 assets × 2 snapshots = 40k slow CEL calls per iter).
//
// Use with -benchtime=3x because each iter is ~1.2s wall-clock
// (40k × 30µs / NumCPU). Default -benchtime=1s runs only one
// iteration and the b.N=1 adaptive growth has no signal.
func BenchmarkBuildLifecyclesPerControl(b *testing.B) {
	cases := []struct {
		name      string
		controls  int
		assets    int
		snapshots int
	}{
		{"100ctl_200asset_2snap", 100, 200, 2},
		{"50ctl_500asset_2snap", 50, 500, 2},
		{"200ctl_100asset_2snap", 200, 100, 2},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			controls, snapshots := buildSyntheticInputs(tc.controls, tc.assets, tc.snapshots)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := BuildLifecyclesPerControl(context.Background(), controls, snapshots, slowPredicateEval); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
