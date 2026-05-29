package cel

import (
	"fmt"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// buildPredicateCatalog manufactures N distinct UnsafePredicate
// values so the benchmark exercises the compile path without any
// in-memory cache hits within a single run.
func buildPredicateCatalog(n int) []policy.UnsafePredicate {
	out := make([]policy.UnsafePredicate, n)
	for i := range n {
		out[i] = policy.UnsafePredicate{
			Any: []policy.PredicateRule{{
				Field: predicate.NewFieldPath(fmt.Sprintf("properties.field_%d", i)),
				Op:    predicate.OpEq,
				Value: policy.NewOperand(false),
			}},
		}
	}
	return out
}

// BenchmarkCompileCatalog_Cold measures full parse + type-check +
// plan for every predicate. This is the pre-cache baseline.
//
// Reset the cache dir to a fresh tempdir per iteration so warm-up
// from a prior iteration does not leak in.
func BenchmarkCompileCatalog_Cold(b *testing.B) {
	preds := buildPredicateCatalog(500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dir := b.TempDir()
		c, err := NewCompiler(WithCacheDir(dir))
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		for _, p := range preds {
			if _, err := c.Compile(p); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkCompileCatalog_Warm measures the cached path: only
// env.Program runs per predicate, no parse, no type-check. The
// setup phase compiles + persists outside the timer.
func BenchmarkCompileCatalog_Warm(b *testing.B) {
	preds := buildPredicateCatalog(500)
	dir := b.TempDir()

	// One-time warm-up: build the on-disk cache.
	setup, err := NewCompiler(WithCacheDir(dir))
	if err != nil {
		b.Fatal(err)
	}
	for _, p := range preds {
		if _, err := setup.Compile(p); err != nil {
			b.Fatal(err)
		}
	}
	if err := setup.PersistCache(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c, err := NewCompiler(WithCacheDir(dir))
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		for _, p := range preds {
			if _, err := c.Compile(p); err != nil {
				b.Fatal(err)
			}
		}
	}
}
