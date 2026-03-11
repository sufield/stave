package app

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/asset"

	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/domain/policy"
	clockadp "github.com/sufield/stave/internal/domain/ports"
)

// BenchmarkEvaluateLargeSnapshot benchmarks evaluation against a large S3 snapshot set.
// This serves as a performance guardrail to ensure evaluation remains performant
// as the codebase evolves.
func BenchmarkEvaluateLargeSnapshot(b *testing.B) {
	// Create a synthetic large observation set for benchmarking
	resources := make([]asset.Asset, 100)
	for i := range 100 {
		resources[i] = asset.Asset{
			ID:     asset.ID("aws:s3:::mvp-bucket-" + string(rune('a'+i%26)) + string(rune('0'+i/26))),
			Type:   kernel.TypeStorageBucket,
			Vendor: kernel.VendorAWS,
			Properties: map[string]any{
				"storage": map[string]any{
					"kind": "s3_bucket",
					"name": "mvp-bucket-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
				},
				"vendor": map[string]any{
					"aws": map[string]any{
						"s3": map[string]any{
							// Some buckets are public to exercise predicate matching.
							"policy_public_statements": func() any {
								if i%3 == 0 {
									return []any{}
								}
								return []any{"s3:GetObject"}
							}(),
						},
					},
				},
			},
		}
	}

	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{
			SchemaVersion: "obs.v0.1",
			CapturedAt:    baseTime,
			Assets:        resources,
		},
		{
			SchemaVersion: "obs.v0.1",
			CapturedAt:    baseTime.Add(10 * 24 * time.Hour), // 10 days later
			Assets:        resources,
		},
	}

	controls := []policy.ControlDefinition{
		{
			DSLVersion:  "ctrl.v1",
			ID:          "CTL.S3.PUBLIC.001",
			Name:        "S3 Bucket Public Read",
			Description: "Buckets should not allow public read access",
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: "properties.storage.kind", Op: "eq", Value: "s3_bucket"},
					{Field: "properties.vendor.aws.s3.policy_public_statements", Op: "list_empty", Value: false},
				},
			},
		},
	}

	clock := clockadp.FixedClock{Time: baseTime.Add(11 * 24 * time.Hour)}
	maxUnsafe := 168 * time.Hour // 7 days

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.Evaluate(service.EvaluateInput{
			Controls:  controls,
			Snapshots: snapshots,
			MaxUnsafe: maxUnsafe,
			Clock:     clock,
		})
	}
}

// TestEvaluationPerformanceGuardrail is a non-flaky test that ensures evaluation
// of 100 assets completes within a reasonable time threshold.
// This is not a strict benchmark but a guardrail against performance regressions.
func TestEvaluationPerformanceGuardrail(t *testing.T) {
	// Create 100 assets similar to a real S3 inventory snapshot
	resources := make([]asset.Asset, 100)
	for i := range 100 {
		resources[i] = asset.Asset{
			ID:     asset.ID("aws:s3:::mvp-rules-bucket-" + string(rune('a'+i%26)) + string(rune('0'+i/26))),
			Type:   kernel.TypeStorageBucket,
			Vendor: kernel.VendorAWS,
			Properties: map[string]any{
				"storage": map[string]any{
					"kind": "s3_bucket",
					"name": "mvp-rules-bucket-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
				},
				"vendor": map[string]any{
					"aws": map[string]any{
						"s3": map[string]any{
							"policy_public_statements": []any{"s3:GetObject"},
						},
					},
				},
			},
		}
	}

	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{
			SchemaVersion: "obs.v0.1",
			CapturedAt:    baseTime,
			Assets:        resources,
		},
		{
			SchemaVersion: "obs.v0.1",
			CapturedAt:    baseTime.Add(10 * 24 * time.Hour),
			Assets:        resources,
		},
	}

	controls := []policy.ControlDefinition{
		{
			DSLVersion:  "ctrl.v1",
			ID:          "CTL.S3.PUBLIC.001",
			Name:        "S3 Bucket Public Read",
			Description: "Test control",
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: "properties.storage.kind", Op: "eq", Value: "s3_bucket"},
					{Field: "properties.vendor.aws.s3.policy_public_statements", Op: "list_empty", Value: false},
				},
			},
		},
	}

	clock := clockadp.FixedClock{Time: baseTime.Add(11 * 24 * time.Hour)}
	maxUnsafe := 168 * time.Hour

	// Run evaluation and measure time
	start := time.Now()
	_, _ = service.Evaluate(service.EvaluateInput{
		Controls:  controls,
		Snapshots: snapshots,
		MaxUnsafe: maxUnsafe,
		Clock:     clock,
	})
	elapsed := time.Since(start)

	// Performance guardrail: evaluation of 100 assets should complete in under 1 second
	// This is a very loose bound to avoid flakiness while still catching major regressions
	maxAllowed := 1 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Evaluation took %v, exceeds guardrail of %v", elapsed, maxAllowed)
	}

	t.Logf("Evaluation of 100 resources completed in %v", elapsed)
}

// TestLargeSnapshotProcessing tests that we can load and process large snapshot inputs
// without memory issues or excessive time.
func TestLargeSnapshotProcessing(t *testing.T) {
	// This test uses in-memory data to avoid file system dependencies
	// The actual loading/parsing is tested via e2e tests.

	// Create 1000 assets to simulate a large S3 inventory.
	resources := make([]asset.Asset, 1000)
	for i := range 1000 {
		resources[i] = asset.Asset{
			ID:     asset.ID("aws:s3:::large-snapshot-" + string(rune('a'+i%26)) + string(rune('0'+(i/26)%10)) + string(rune('0'+(i/260)%10))),
			Type:   kernel.TypeStorageBucket,
			Vendor: kernel.VendorAWS,
			Properties: map[string]any{
				"storage": map[string]any{
					"kind": "s3_bucket",
					"name": "large-snapshot-" + string(rune('a'+i%26)),
				},
			},
		}
	}

	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshot := asset.Snapshot{
		SchemaVersion: "obs.v0.1",
		CapturedAt:    baseTime,
		Assets:        resources,
	}

	// Verify we can create timelines for 1000 assets
	ctl := policy.ControlDefinition{
		DSLVersion:  "ctrl.v1",
		ID:          "CTL.TEST.001",
		Name:        "Test Control",
		Type:        policy.TypeUnsafeDuration,
		Description: "Always triggers for S3 buckets",
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: "properties.storage.kind", Op: "eq", Value: "s3_bucket"},
			},
		},
	}
	_ = ctl.Prepare()
	controls := []policy.ControlDefinition{ctl}

	clock := clockadp.FixedClock{Time: baseTime.Add(1 * time.Hour)}
	maxUnsafe := 168 * time.Hour

	start := time.Now()
	result, err := service.Evaluate(service.EvaluateInput{
		Controls:  controls,
		Snapshots: []asset.Snapshot{snapshot},
		MaxUnsafe: maxUnsafe,
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	elapsed := time.Since(start)

	// Verify results
	if result.Summary.AssetsEvaluated != 1000 {
		t.Errorf("Expected 1000 resources evaluated, got %d", result.Summary.AssetsEvaluated)
	}

	// Performance guardrail: 1000 assets should complete in under 5 seconds
	maxAllowed := 5 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Large snapshot evaluation took %v, exceeds guardrail of %v", elapsed, maxAllowed)
	}

	t.Logf("Evaluation of 1000 resources completed in %v", elapsed)
}
