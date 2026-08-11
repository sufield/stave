package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
)

// benchPredicateEval is the always-unsafe predicate evaluator the
// benchmarks wire into Assessor.predicateEval. Every asset×control
// pair evaluates true, so the full per-asset finding-generation
// path runs (collector writes, span lifecycle, recordings). Mirrors
// testbuilder_test.go's newTestAssessor.alwaysUnsafe() pattern.
//
// Wiring this matters: before it was added, every Bench*Evaluate*
// benchmark constructed Assessor via struct literal without
// predicateEval, and Assess() bailed at the precondition check
// returning errors.New("precondition failed: Assessor requires a
// PredicateEval"). The reported ~200 ns/op figures were the
// error-string-construction cost, not the evaluation cost.
var benchPredicateEval policy.PredicateEval = func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
	return true, nil
}

// benchPredicateParser pairs with benchPredicateEval. Returns an
// empty UnsafePredicate so the parser-required precondition passes
// without affecting evaluation (the predicates are pre-built on
// the controls themselves).
var benchPredicateParser = func(_ any) (*policy.UnsafePredicate, error) {
	return &policy.UnsafePredicate{}, nil
}

// benchNopDigester satisfies ports.Digester so FingerprintPolicy()
// stops logging "called without a Digester" warnings that
// interleave with benchmark output. Production wires a real
// crypto.NewHasher() via WithHasher; the benchmark only needs the
// interface satisfied, not a real digest.
type benchNopDigester struct{}

func (benchNopDigester) Digest(_ []string, _ byte) kernel.Digest { return "" }

// benchAssessor returns a *Assessor pre-wired with every
// precondition Assess() requires (clock, SLA, predicate eval +
// parser, hasher) so callers only have to supply controls. Builds
// the spine the four benchmarks share; the per-benchmark caller
// only varies controls and slaThreshold via the returned struct's
// fields. Centralising the wiring is what prevents future
// benchmarks from reintroducing the precondition-error-path bug.
func benchAssessor(now time.Time, sla time.Duration, controls []policy.ControlDefinition) *Assessor {
	return &Assessor{
		controls:        controls,
		slaThreshold:    sla,
		clock:           ports.FixedClock(now),
		predicateEval:   benchPredicateEval,
		predicateParser: benchPredicateParser,
		hasher:          benchNopDigester{},
	}
}

// mustAssessSucceed runs Assess once outside the timer and fails
// the benchmark immediately if it returns an error. The original
// benchmarks discarded errors via `_, _ = ...`, which is how the
// precondition-error bug went unnoticed for so long. Calling this
// at the top of every benchmark catches future precondition
// regressions (forgot to wire predicateEval, missing clock, etc.)
// before they inflate the ns/op number with the error-return path.
func mustAssessSucceed(b *testing.B, a *Assessor, snapshots []asset.Snapshot) {
	b.Helper()
	if _, err := a.Assess(context.Background(), snapshots); err != nil {
		b.Fatalf("Assess returned error (benchmark precondition not wired): %v", err)
	}
}

// BenchmarkEvaluate measures evaluation of controls across asset lifecycles.
// Run with: go test -bench=BenchmarkEvaluate -benchmem ./internal/core/evaluation/engine/
func BenchmarkEvaluate(b *testing.B) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.BENCH.001",
			Name: "bench-unsafe-state",
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		{
			ID:   "CTL.BENCH.002",
			Name: "bench-unsafe-duration",
			Type: policy.TypeUnsafeDuration,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.encryption_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
	}

	snapshots := buildBenchmarkSnapshots(now, 20)

	for i := range controls {
		if err := controls[i].Prepare(); err != nil {
			b.Fatal(err)
		}
	}

	assessor := benchAssessor(now, 12*time.Hour, controls)

	// Sanity-check the precondition once outside the timer so a
	// future config regression fails loudly instead of inflating
	// the ns/op number with the error-return path.
	mustAssessSucceed(b, assessor, snapshots)

	b.ResetTimer()
	for b.Loop() {
		_, _ = assessor.Assess(context.Background(), snapshots)
	}
}

// BenchmarkEvaluate10kAssets measures evaluation throughput at production scale.
// This is the primary performance guardrail — if this regresses, investigate
// before merging. Run: go test -bench=BenchmarkEvaluate10k -benchmem ./internal/core/evaluation/engine/
func BenchmarkEvaluate10kAssets(b *testing.B) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	// Mixed S3 + IAM controls — exercises multi-domain evaluation.
	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.BENCH.S3.001",
			Name: "bench-public-read",
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		{
			ID:   "CTL.BENCH.S3.002",
			Name: "bench-no-encryption",
			Type: policy.TypeUnsafeDuration,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
					{Field: predicate.NewFieldPath("properties.storage.encryption.at_rest_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		{
			ID:   "CTL.BENCH.S3.003",
			Name: "bench-no-pab",
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
					{Field: predicate.NewFieldPath("properties.storage.controls.public_access_fully_blocked"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		{
			ID:   "CTL.BENCH.IAM.001",
			Name: "bench-root-mfa",
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.identity.kind"), Op: predicate.OpEq, Value: policy.Str("account")},
					{Field: predicate.NewFieldPath("properties.identity.root.mfa_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		{
			ID:   "CTL.BENCH.IAM.002",
			Name: "bench-unused-creds",
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.identity.kind"), Op: predicate.OpEq, Value: policy.Str("user")},
					{Field: predicate.NewFieldPath("properties.identity.credentials.unused"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
	}

	snapshots := buildBenchmarkSnapshots(now, 10_000)

	for i := range controls {
		if err := controls[i].Prepare(); err != nil {
			b.Fatal(err)
		}
	}

	assessor := benchAssessor(now, 168*time.Hour, controls)

	mustAssessSucceed(b, assessor, snapshots)

	b.ResetTimer()
	for b.Loop() {
		_, _ = assessor.Assess(context.Background(), snapshots)
	}
}

// BenchmarkEvaluateMultiControlScaling measures how evaluation scales with
// control count on a fixed asset set. This catches O(n*m) regressions where
// n=assets and m=controls.
func BenchmarkEvaluateMultiControlScaling(b *testing.B) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	snapshots := buildBenchmarkSnapshots(now, 1_000)

	for _, ctlCount := range []int{1, 5, 10, 25, 50} {
		controls := make([]policy.ControlDefinition, ctlCount)
		for i := range ctlCount {
			controls[i] = policy.ControlDefinition{
				ID:   kernel.ControlID(fmt.Sprintf("CTL.SCALE.%03d", i)),
				Name: fmt.Sprintf("scale-control-%d", i),
				Type: policy.TypeUnsafeState,
				UnsafePredicate: policy.UnsafePredicate{
					Any: []policy.PredicateRule{
						{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
					},
				},
			}
			if err := controls[i].Prepare(); err != nil {
				b.Fatal(err)
			}
		}

		assessor := benchAssessor(now, 168*time.Hour, controls)

		mustAssessSucceed(b, assessor, snapshots)

		b.Run(fmt.Sprintf("controls=%d", ctlCount), func(b *testing.B) {
			for b.Loop() {
				_, _ = assessor.Assess(context.Background(), snapshots)
			}
		})
	}
}

func buildBenchmarkSnapshots(baseTime time.Time, assetCount int) []asset.Snapshot {
	assets1 := make([]asset.Asset, assetCount)
	assets2 := make([]asset.Asset, assetCount)
	for i := range assetCount {
		a := buildBenchmarkAsset(i)
		assets1[i] = a
		assets2[i] = a
	}
	return []asset.Snapshot{
		{CapturedAt: baseTime.Add(-24 * time.Hour), Assets: assets1},
		{CapturedAt: baseTime, Assets: assets2},
	}
}

// buildBenchmarkAsset creates a mixed S3/IAM asset based on index.
// Distribution: 70% S3 buckets, 20% IAM users, 10% IAM accounts.
func buildBenchmarkAsset(i int) asset.Asset {
	switch {
	case i%10 == 0: // 10% IAM accounts
		return asset.Asset{
			ID:     asset.ID(fmt.Sprintf("aws-account-%d", i)),
			Type:   "aws_iam_account",
			Vendor: "aws",
			Properties: map[string]any{
				"identity": map[string]any{
					"kind": "account",
					"root": map[string]any{
						"mfa_enabled":     i%4 != 0, // 25% missing MFA
						"has_access_keys": i%7 == 0, // ~14% have keys
					},
				},
			},
		}
	case i%5 == 0: // 20% IAM users
		return asset.Asset{
			ID:     asset.ID(fmt.Sprintf("iam-user-%d", i)),
			Type:   "aws_iam_user",
			Vendor: "aws",
			Properties: map[string]any{
				"identity": map[string]any{
					"kind": "user",
					"console_access": map[string]any{
						"enabled":     true,
						"mfa_enabled": i%3 != 0, // 33% missing MFA
					},
					"credentials": map[string]any{
						"unused": i%8 == 0, // 12.5% unused
					},
					"access_keys": map[string]any{
						"has_stale_key": i%6 == 0, // ~16% stale
					},
					"policies": map[string]any{
						"has_inline_policies": i%9 == 0,
						"has_direct_policies": i%11 == 0,
					},
				},
			},
		}
	default: // 70% S3 buckets
		return asset.Asset{
			ID:     asset.ID(fmt.Sprintf("arn:aws:s3:::bucket-%d", i)),
			Type:   "aws_s3_bucket",
			Vendor: "aws",
			Properties: map[string]any{
				"storage": map[string]any{
					"kind": "bucket",
					"access": map[string]any{
						"public_read":  i%3 == 0,
						"public_list":  i%4 == 0,
						"public_write": false,
					},
					"encryption": map[string]any{
						"at_rest_enabled": i%5 != 0,
					},
					"controls": map[string]any{
						"public_access_fully_blocked": i%2 == 0,
					},
				},
			},
		}
	}
}

// BenchmarkEvaluateLargeScale exercises the per-control parallelism added
// in Phase 2 of the evaluation optimisation track. The pre-Phase-2
// sequential baseline (captured 2026-05-21 in docs/perf/evaluation-baseline.md)
// reported sub-microsecond per-op cost on the small-N benchmarks — because
// those benchmarks have so few controls that the per-control loop is
// dominated by setup. The realistic case is 2,000+ controls × 100+ assets,
// where the parallel dispatch actually has work to spread across cores.
//
// Run sequential vs parallel comparison with:
//
//	go test -run=^$ -bench=BenchmarkEvaluateLargeScale -benchtime=3s \
//	  -cpu=1,8 ./internal/core/evaluation/engine/
//
// The -cpu=1 invocation pins GOMAXPROCS=1 (errgroup still schedules
// goroutines, but they all run on one OS thread — close to sequential
// behaviour). The -cpu=8 invocation uses all 8 cores. The ratio between
// the two is the apples-to-apples parallelism speedup.
//
// Acceptance criteria from docs/perf/evaluation-baseline.md:
//   - No regression at -cpu=1 vs the historical sequential baseline.
//   - 3-5× speedup at -cpu=8 if the per-control work parallelises cleanly.
func BenchmarkEvaluateLargeScale(b *testing.B) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	// Build 2,000 synthetic controls across four predicate shapes —
	// enough to make per-control dispatch visible against setup.
	const controlCount = 2_000
	controls := make([]policy.ControlDefinition, controlCount)
	for i := range controlCount {
		var pred policy.UnsafePredicate
		switch i % 4 {
		case 0: // public-read check
			pred = policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			}
		case 1: // encryption check
			pred = policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
					{Field: predicate.NewFieldPath("properties.storage.encryption.at_rest_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			}
		case 2: // public-list check
			pred = policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_list"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			}
		default: // PAB check
			pred = policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
					{Field: predicate.NewFieldPath("properties.storage.controls.public_access_fully_blocked"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			}
		}
		controls[i] = policy.ControlDefinition{
			ID:              kernel.ControlID(fmt.Sprintf("CTL.LARGE.%04d", i)),
			Name:            fmt.Sprintf("large-control-%d", i),
			Type:            policy.TypeUnsafeState,
			UnsafePredicate: pred,
		}
		if err := controls[i].Prepare(); err != nil {
			b.Fatal(err)
		}
	}

	// 200 assets per snapshot — large enough that the per-control inner
	// loop has real work, small enough to keep benchmark wall time
	// reasonable.
	snapshots := buildBenchmarkSnapshots(now, 200)

	assessor := benchAssessor(now, 168*time.Hour, controls)

	mustAssessSucceed(b, assessor, snapshots)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = assessor.Assess(context.Background(), snapshots)
	}
}
