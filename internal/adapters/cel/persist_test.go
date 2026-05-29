package cel

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// helper: build a minimal CheckedExpr for a real CEL expression.
// Using the live env makes the round-trip realistic; mocking the
// proto would let the encoder pass on shapes that the consumer
// would reject at env.Program time.
func mustCompile(t *testing.T, env *cel.Env, expr string) *exprpb.CheckedExpr {
	t.Helper()
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile %q: %v", expr, issues.Err())
	}
	ce, err := astToCheckedExpr(ast)
	if err != nil {
		t.Fatalf("ast to checked-expr: %v", err)
	}
	return ce
}

func envForTest(t *testing.T) *cel.Env {
	t.Helper()
	env, err := NewEnv()
	if err != nil {
		t.Fatalf("NewEnv: %v", err)
	}
	return env
}

func entryFor(t *testing.T, env *cel.Env, expr string) cachedEntry {
	t.Helper()
	return cachedEntry{
		ExpressionSHA: hashExpression(expr),
		Expression:    expr,
		CheckedExpr:   mustCompile(t, env, expr),
	}
}

func TestPersist_RoundTrip(t *testing.T) {
	env := envForTest(t)
	in := []cachedEntry{
		entryFor(t, env, `1 == 1`),
		entryFor(t, env, `"a" + "b" == "ab"`),
	}
	dir := t.TempDir()
	path := cacheFilePath(dir)
	if err := persistCacheFile(path, in); err != nil {
		t.Fatalf("persist: %v", err)
	}
	out, err := loadCacheFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("entry count: want %d, got %d", len(in), len(out))
	}
	for i := range in {
		if in[i].Expression != out[i].Expression {
			t.Errorf("expression[%d]: want %q got %q", i, in[i].Expression, out[i].Expression)
		}
		if in[i].ExpressionSHA != out[i].ExpressionSHA {
			t.Errorf("sha[%d] differs", i)
		}
		// Round-trip the CheckedExpr through env.Program to confirm
		// it is semantically intact, not just byte-identical.
		ast := checkedExprToAst(out[i].CheckedExpr)
		if _, err := env.Program(ast); err != nil {
			t.Errorf("env.Program after round-trip [%d]: %v", i, err)
		}
	}
}

func TestPersist_MissingFileIsNotError(t *testing.T) {
	out, err := loadCacheFile(filepath.Join(t.TempDir(), "nope.pb"))
	if err != nil {
		t.Fatalf("missing file should return (nil, nil), got err: %v", err)
	}
	if out != nil {
		t.Fatalf("missing file should return nil entries, got %d", len(out))
	}
}

func TestPersist_TruncatedHeaderIsDetected(t *testing.T) {
	dir := t.TempDir()
	path := cacheFilePath(dir)
	// Truncated to magic only — no format version, no version
	// string, no entry count. The reader should fail cleanly at the
	// first missing field rather than panic.
	if err := os.WriteFile(path, []byte(cacheMagic), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadCacheFile(path)
	if err == nil {
		t.Fatalf("expected decode error on truncated header")
	}
}

func TestPersist_BadMagicIsDetected(t *testing.T) {
	dir := t.TempDir()
	path := cacheFilePath(dir)
	if err := os.WriteFile(path, []byte("WRONG\x00\x00\x00"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadCacheFile(path)
	if err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("expected magic mismatch, got %v", err)
	}
}

func TestPersist_FormatVersionMismatchIsDetected(t *testing.T) {
	dir := t.TempDir()
	path := cacheFilePath(dir)
	// Hand-build a header with format version 999.
	buf := []byte(cacheMagic)
	buf = appendUint32(buf, 999)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadCacheFile(path)
	if err == nil || !strings.Contains(err.Error(), "format version") {
		t.Fatalf("expected format-version error, got %v", err)
	}
}

func TestPersist_CelGoVersionMismatchIsDetected(t *testing.T) {
	dir := t.TempDir()
	path := cacheFilePath(dir)
	bogusVersion := "v0.0.0-bogus"
	buf := []byte(cacheMagic)
	buf = appendUint32(buf, cacheFormatVersion)
	buf = appendUint32(buf, uint32(len(bogusVersion)))
	buf = append(buf, bogusVersion...)
	buf = appendUint64(buf, 0)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadCacheFile(path)
	if err == nil || !strings.Contains(err.Error(), "cel-go version") {
		t.Fatalf("expected cel-go version error, got %v", err)
	}
}

func TestPersist_ShaMismatchPoisoningDefense(t *testing.T) {
	// The on-disk format stores both the expression string and an
	// independent SHA of it. The load-bearing correctness check
	// happens at the compiler boundary (TestCompiler_PoisonedCache),
	// but the persist layer should still expose enough information
	// for that check to run: an entry whose stored SHA does not
	// match its stored expression is a smoking gun for cache
	// corruption.
	env := envForTest(t)
	e := entryFor(t, env, `1 == 1`)
	// Tamper: keep the SHA of "1 == 1" but change the expression.
	e.Expression = `2 == 2`
	dir := t.TempDir()
	path := cacheFilePath(dir)
	if err := persistCacheFile(path, []cachedEntry{e}); err != nil {
		t.Fatalf("persist: %v", err)
	}
	out, err := loadCacheFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out[0].ExpressionSHA == hashExpression(out[0].Expression) {
		t.Fatalf("expected SHA mismatch on tampered entry")
	}
	// Recompute the SHA — this is what the compiler will do.
	live := sha256.Sum256([]byte(out[0].Expression))
	if live == out[0].ExpressionSHA {
		t.Fatalf("live SHA should not match poisoned stored SHA")
	}
}

func TestPersist_AtomicWriteVisibleAtFullSize(t *testing.T) {
	// Atomicity contract: after persistCacheFile returns, any
	// concurrent reader sees either no file or the full file —
	// never a half-written one. The rename-based implementation
	// satisfies this on POSIX. We exercise it by writing once and
	// confirming the file size matches a fresh encode of the same
	// entries.
	env := envForTest(t)
	in := []cachedEntry{entryFor(t, env, `1 + 2 == 3`)}
	dir := t.TempDir()
	path := cacheFilePath(dir)
	if err := persistCacheFile(path, in); err != nil {
		t.Fatalf("persist: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != int64(len(encodeCache(in))) {
		t.Fatalf("file size %d != encoded size %d", info.Size(), len(encodeCache(in)))
	}
	// Verify no stray .tmp files remain in the cache dir.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestPersist_ConcurrentWritersLastWriteWins(t *testing.T) {
	env := envForTest(t)
	dir := t.TempDir()
	path := cacheFilePath(dir)

	const writers = 8
	in := []cachedEntry{entryFor(t, env, `1 == 1`)}
	var wg sync.WaitGroup
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			if err := persistCacheFile(path, in); err != nil {
				t.Errorf("persist: %v", err)
			}
		}()
	}
	wg.Wait()

	out, err := loadCacheFile(path)
	if err != nil {
		t.Fatalf("load after concurrent writes: %v", err)
	}
	if len(out) != 1 || out[0].Expression != "1 == 1" {
		t.Fatalf("unexpected post-race state: %+v", out)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file after concurrent writes: %s", e.Name())
		}
	}
}

func TestPersist_IsCacheDisabledHonorsEnv(t *testing.T) {
	t.Setenv(disableCacheEnv, "")
	if IsCacheDisabled() {
		t.Fatalf("expected enabled with empty env")
	}
	t.Setenv(disableCacheEnv, "1")
	if !IsCacheDisabled() {
		t.Fatalf("expected disabled with non-empty env")
	}
}
