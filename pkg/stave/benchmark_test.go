package stave_test

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/stave"
)

func BenchmarkApply(b *testing.B) {
	cfg := stave.Config{
		SnapshotsDir: lordofheavenSnapshots,
		Now:          frozenNow,
	}
	ctx := context.Background()

	// Warm up: one run to populate CEL compile cache
	if _, err := stave.Apply(ctx, cfg); err != nil {
		b.Fatalf("warmup: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := stave.Apply(ctx, cfg)
		if err != nil {
			b.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func BenchmarkApplyColdStart(b *testing.B) {
	cfg := stave.Config{
		SnapshotsDir: lordofheavenSnapshots,
		Now:          time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := stave.Apply(ctx, cfg)
		if err != nil {
			b.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func BenchmarkValidate(b *testing.B) {
	cfg := stave.ValidateConfig{
		SnapshotsDir: lordofheavenSnapshots,
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := stave.Validate(ctx, cfg)
		if err != nil {
			b.Fatalf("iteration %d: %v", i, err)
		}
	}
}
