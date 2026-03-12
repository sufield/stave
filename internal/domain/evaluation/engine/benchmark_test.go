package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// BenchmarkEvaluate measures evaluation of controls across asset timelines.
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
					{Field: "properties.public", Op: "eq", Value: true},
				},
			},
		},
		{
			ID:   "CTL.BENCH.002",
			Name: "bench-unsafe-duration",
			Type: policy.TypeUnsafeDuration,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: "properties.encryption_enabled", Op: "eq", Value: false},
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

	runner := &Runner{
		Controls:  controls,
		MaxUnsafe: 12 * time.Hour,
		Clock:     ports.FixedClock(now),
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = runner.Evaluate(snapshots)
	}
}

func buildBenchmarkSnapshots(baseTime time.Time, assetCount int) []asset.Snapshot {
	assets1 := make([]asset.Asset, assetCount)
	assets2 := make([]asset.Asset, assetCount)
	for i := range assetCount {
		id := asset.ID(fmt.Sprintf("arn:aws:s3:::bucket-%d", i))
		assets1[i] = asset.Asset{
			ID:     id,
			Type:   "aws_s3_bucket",
			Vendor: "aws",
			Properties: map[string]any{
				"public":             i%3 == 0,
				"encryption_enabled": i%5 != 0,
			},
		}
		assets2[i] = asset.Asset{
			ID:     id,
			Type:   "aws_s3_bucket",
			Vendor: "aws",
			Properties: map[string]any{
				"public":             i%3 == 0,
				"encryption_enabled": i%5 != 0,
			},
		}
	}
	return []asset.Snapshot{
		{CapturedAt: baseTime.Add(-24 * time.Hour), Assets: assets1},
		{CapturedAt: baseTime, Assets: assets2},
	}
}
