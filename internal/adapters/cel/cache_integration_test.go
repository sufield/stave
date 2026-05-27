package cel

import (
	"os"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// Integration tests for the persistent CEL compile cache, exercised
// through the Compiler boundary (not the persist layer alone). The
// scenarios that matter: warm-start equality with cold-start
// behaviour, poisoned-cache rejection, and corrupt-file fallback.

func samplePredicate() policy.UnsafePredicate {
	return policy.UnsafePredicate{
		Any: []policy.PredicateRule{{
			Field: predicate.NewFieldPath("properties.encryption_at_rest"),
			Op:    predicate.OpEq,
			Value: policy.NewOperand(false),
		}},
	}
}

func samplePredicate2() policy.UnsafePredicate {
	return policy.UnsafePredicate{
		All: []policy.PredicateRule{{
			Field: predicate.NewFieldPath("properties.public_access"),
			Op:    predicate.OpEq,
			Value: policy.NewOperand(true),
		}},
	}
}

func TestCache_WarmStartHitsDiskCache(t *testing.T) {
	dir := t.TempDir()

	// Cold compiler: compile + persist.
	cold, err := NewCompiler(WithCacheDir(dir))
	if err != nil {
		t.Fatalf("cold compiler: %v", err)
	}
	cp1, err := cold.Compile(samplePredicate())
	if err != nil {
		t.Fatalf("cold compile: %v", err)
	}
	if err := cold.PersistCache(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if _, err := os.Stat(cacheFilePath(dir)); err != nil {
		t.Fatalf("cache file missing after persist: %v", err)
	}

	// Warm compiler: should pick up the cached CheckedExpr.
	warm, err := NewCompiler(WithCacheDir(dir))
	if err != nil {
		t.Fatalf("warm compiler: %v", err)
	}
	if _, hit := warm.diskCache[string(cp1.Expression)]; !hit {
		t.Fatalf("expected disk cache to contain expression %q", cp1.Expression)
	}
	cp2, err := warm.Compile(samplePredicate())
	if err != nil {
		t.Fatalf("warm compile: %v", err)
	}
	if cp1.Expression != cp2.Expression {
		t.Fatalf("expression drift: %q != %q", cp1.Expression, cp2.Expression)
	}
	if !cp2.IsValid() {
		t.Fatalf("warm compiler returned invalid CompiledPredicate")
	}
}

func TestCache_NewExpressionGetsPersistedOnNextWrite(t *testing.T) {
	dir := t.TempDir()
	// Cold compiler with one predicate.
	cold, _ := NewCompiler(WithCacheDir(dir))
	if _, err := cold.Compile(samplePredicate()); err != nil {
		t.Fatal(err)
	}
	if err := cold.PersistCache(); err != nil {
		t.Fatal(err)
	}

	// Warm compiler, second predicate appears.
	warm, _ := NewCompiler(WithCacheDir(dir))
	if _, err := warm.Compile(samplePredicate()); err != nil {
		t.Fatal(err)
	}
	if _, err := warm.Compile(samplePredicate2()); err != nil {
		t.Fatal(err)
	}
	if err := warm.PersistCache(); err != nil {
		t.Fatal(err)
	}

	// Third compiler should see both expressions on disk.
	third, _ := NewCompiler(WithCacheDir(dir))
	if len(third.diskCache) != 2 {
		t.Fatalf("expected 2 cached expressions, got %d: %v",
			len(third.diskCache), keysOf(third.diskCache))
	}
}

func TestCache_PoisonedSHAIsRejected(t *testing.T) {
	dir := t.TempDir()

	// Build a cache file by hand: one entry whose stored SHA does
	// NOT match the stored expression. The compiler load path must
	// drop this entry rather than serve the wrong AST.
	env := envForTest(t)
	expr := `1 == 1`
	good := cachedEntry{
		ExpressionSHA: hashExpression(expr),
		Expression:    expr,
		CheckedExpr:   mustCompile(t, env, expr),
	}
	bad := cachedEntry{
		ExpressionSHA: hashExpression(`completely-different`), // wrong SHA
		Expression:    expr,
		CheckedExpr:   mustCompile(t, env, expr),
	}
	if err := persistCacheFile(cacheFilePath(dir), []cachedEntry{good, bad}); err != nil {
		t.Fatalf("persist: %v", err)
	}

	c, err := NewCompiler(WithCacheDir(dir))
	if err != nil {
		t.Fatalf("compiler: %v", err)
	}
	// Only the good entry should survive the load.
	if len(c.diskCache) != 1 {
		t.Fatalf("expected 1 entry after poisoning defense, got %d", len(c.diskCache))
	}
	if _, ok := c.diskCache[expr]; !ok {
		t.Fatalf("good entry missing from diskCache: %v", keysOf(c.diskCache))
	}
}

func TestCache_CorruptFileFallsBackToCold(t *testing.T) {
	dir := t.TempDir()
	// Write garbage where the cache file should be.
	if err := os.WriteFile(cacheFilePath(dir), []byte("garbage not pb"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := NewCompiler(WithCacheDir(dir))
	if err != nil {
		t.Fatalf("compiler must not error on corrupt cache: %v", err)
	}
	if len(c.diskCache) != 0 {
		t.Fatalf("expected empty diskCache after corrupt load, got %d", len(c.diskCache))
	}
	// Cold compilation still works.
	if _, err := c.Compile(samplePredicate()); err != nil {
		t.Fatalf("compile after corrupt cache: %v", err)
	}
}

func TestCache_KillSwitchShortCircuits(t *testing.T) {
	t.Setenv(disableCacheEnv, "1")
	dir := t.TempDir()
	c, err := NewCompiler(WithCacheDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Compile(samplePredicate()); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistCache(); err != nil {
		t.Fatalf("persist should be a no-op under kill-switch: %v", err)
	}
	if _, err := os.Stat(cacheFilePath(dir)); !os.IsNotExist(err) {
		t.Fatalf("kill-switch must not write cache file: %v", err)
	}
}

func TestCache_DefaultsToNoDiskWhenNoOption(t *testing.T) {
	// Pre-cache default: NewCompiler() without WithCacheDir does no
	// disk I/O, regardless of XDG_CACHE_HOME state. This is the
	// safety contract for the 8 existing callers we haven't wired
	// yet — they keep getting the original in-memory-only behaviour.
	c, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if c.cacheDir != "" {
		t.Fatalf("cacheDir should be empty by default, got %q", c.cacheDir)
	}
	if err := c.PersistCache(); err != nil {
		t.Fatalf("persist with no cacheDir should be no-op: %v", err)
	}
}

func TestCache_EvaluationIsByteIdenticalColdVsWarm(t *testing.T) {
	// Determinism contract: the expression string is the cache
	// key, so cold and warm compilers must produce CompiledPredicates
	// whose Expression field matches exactly. Anything that breaks
	// this would manifest as report drift after a cache hit.
	dir := t.TempDir()
	preds := []policy.UnsafePredicate{samplePredicate(), samplePredicate2()}

	cold, _ := NewCompiler(WithCacheDir(dir))
	coldOut := make([]CELExpression, len(preds))
	for i, p := range preds {
		cp, err := cold.Compile(p)
		if err != nil {
			t.Fatalf("cold %d: %v", i, err)
		}
		coldOut[i] = cp.Expression
	}
	if err := cold.PersistCache(); err != nil {
		t.Fatal(err)
	}

	warm, _ := NewCompiler(WithCacheDir(dir))
	for i, p := range preds {
		cp, err := warm.Compile(p)
		if err != nil {
			t.Fatalf("warm %d: %v", i, err)
		}
		if cp.Expression != coldOut[i] {
			t.Errorf("expression drift at %d:\n  cold: %s\n  warm: %s", i, coldOut[i], cp.Expression)
		}
	}
}

// helpers

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
