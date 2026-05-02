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

// BenchmarkEvaluate measures evaluation of controls across asset lifecycles.
// Run with: go test -bench=BenchmarkEvaluate -benchmem ./internal/domain/evaluation/engine/
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

	assessor := &Assessor{
		controls:     controls,
		slaThreshold: 12 * time.Hour,
		clock:        ports.FixedClock(now),
	}

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

	assessor := &Assessor{
		controls:     controls,
		slaThreshold: 168 * time.Hour,
		clock:        ports.FixedClock(now),
	}

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

		assessor := &Assessor{
			controls:     controls,
			slaThreshold: 168 * time.Hour,
			clock:        ports.FixedClock(now),
		}

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
