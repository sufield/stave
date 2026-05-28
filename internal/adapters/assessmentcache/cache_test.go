package assessmentcache

import (
	"os"
	"path/filepath"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func sampleKey() Key {
	return Key{
		StaveVersion:    "v0.1.0",
		ControlsDigest:  "abc123",
		InputHashesHash: "def456",
		ChainsDigest:    "no-chains",
		ConfigDigest:    "cfg789",
	}
}

func sampleReport() evaluation.ComplianceReport {
	return evaluation.ComplianceReport{
		SecurityState: evaluation.StateCompliant,
		Findings:      []evaluation.Finding{},
	}
}

func TestCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	k := sampleKey()
	want := sampleReport()

	if _, ok := c.Load(k); ok {
		t.Fatal("empty cache should miss")
	}
	if err := c.Persist(k, want); err != nil {
		t.Fatalf("persist: %v", err)
	}
	got, ok := c.Load(k)
	if !ok {
		t.Fatal("post-persist load should hit")
	}
	if got.SecurityState != want.SecurityState {
		t.Errorf("state drift: %v vs %v", got.SecurityState, want.SecurityState)
	}
}

func TestCache_DisabledByEnv(t *testing.T) {
	t.Setenv(disableEnv, "1")
	dir := t.TempDir()
	c := New(dir)
	if err := c.Persist(sampleKey(), sampleReport()); err != nil {
		t.Fatalf("persist under kill-switch should be a no-op: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("kill-switch must not write files: %d entries", len(entries))
	}
	if _, ok := c.Load(sampleKey()); ok {
		t.Fatal("kill-switch must short-circuit Load")
	}
}

func TestCache_EmptyDirIsNoop(t *testing.T) {
	c := New("")
	if err := c.Persist(sampleKey(), sampleReport()); err != nil {
		t.Fatalf("persist with empty dir should be a no-op: %v", err)
	}
	if _, ok := c.Load(sampleKey()); ok {
		t.Fatal("empty dir must short-circuit Load")
	}
}

func TestCache_DifferentKeysIndependent(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	k1 := sampleKey()
	k2 := sampleKey()
	k2.ControlsDigest = "different"

	r1 := sampleReport()
	r1.SecurityState = evaluation.StateCompliant
	r2 := sampleReport()
	r2.SecurityState = evaluation.StateNonCompliant

	if err := c.Persist(k1, r1); err != nil {
		t.Fatal(err)
	}
	if err := c.Persist(k2, r2); err != nil {
		t.Fatal(err)
	}
	got1, _ := c.Load(k1)
	got2, _ := c.Load(k2)
	if got1.SecurityState != evaluation.StateCompliant {
		t.Errorf("k1 returned wrong report: %v", got1.SecurityState)
	}
	if got2.SecurityState != evaluation.StateNonCompliant {
		t.Errorf("k2 returned wrong report: %v", got2.SecurityState)
	}
}

func TestCache_CorruptFileMisses(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	k := sampleKey()
	// Write garbage where a cache file would be — Load should
	// return miss, NOT panic, NOT propagate an error.
	path := filepath.Join(dir, k.Hex()+".json")
	if err := os.WriteFile(path, []byte("not a cache file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Load(k); ok {
		t.Fatal("corrupt file should miss, not hit")
	}
}

func TestCache_TamperedKeyDetected(t *testing.T) {
	// The key embedded in the file body must match the key the
	// caller passed to Load. A mismatch means the file basename
	// was renamed or the file was edited — drop, don't trust.
	dir := t.TempDir()
	c := New(dir)
	k := sampleKey()
	if err := c.Persist(k, sampleReport()); err != nil {
		t.Fatal(err)
	}

	// Read the persisted bytes, then write them under a DIFFERENT
	// key's basename. The decoder reads the embedded key from the
	// body and compares to the caller's key — mismatch should miss.
	body, err := os.ReadFile(filepath.Join(dir, k.Hex()+".json"))
	if err != nil {
		t.Fatal(err)
	}
	differentKey := k
	differentKey.ControlsDigest = "completely-different"
	if err := os.WriteFile(filepath.Join(dir, differentKey.Hex()+".json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Load(differentKey); ok {
		t.Fatal("tampered file (key-basename != embedded-key) must miss")
	}
}

func TestKey_HexIsDeterministic(t *testing.T) {
	a := sampleKey()
	b := sampleKey()
	if a.Hex() != b.Hex() {
		t.Fatal("same fields must produce the same hex")
	}
	c := sampleKey()
	c.ControlsDigest = "tweaked"
	if a.Hex() == c.Hex() {
		t.Fatal("different fields must produce different hex")
	}
}

func TestComputeControlsDigest_StableUnderReorder(t *testing.T) {
	// Reordering the input slice must not change the digest.
	// The digest is the canonical ID-sorted JSON concatenation.
	c1 := []policy.ControlDefinition{
		{ID: "B", Name: "two"},
		{ID: "A", Name: "one"},
	}
	c2 := []policy.ControlDefinition{
		{ID: "A", Name: "one"},
		{ID: "B", Name: "two"},
	}
	if ComputeControlsDigest(c1) != ComputeControlsDigest(c2) {
		t.Fatal("reordering must not change the digest")
	}
}

func TestComputeControlsDigest_DriftsOnFieldEdit(t *testing.T) {
	c1 := []policy.ControlDefinition{{ID: "A", Name: "one"}}
	c2 := []policy.ControlDefinition{{ID: "A", Name: "ONE"}}
	if ComputeControlsDigest(c1) == ComputeControlsDigest(c2) {
		t.Fatal("any field edit must rotate the digest")
	}
}

func TestComputeInputHashesKey_PrefersOverall(t *testing.T) {
	got := ComputeInputHashesKey(&evaluation.InputHashes{
		Overall: kernel.Digest("aggregate-hash"),
	})
	if got != "aggregate-hash" {
		t.Fatalf("expected 'aggregate-hash', got %q", got)
	}
}

func TestComputeInputHashesKey_FallsBackToPerFile(t *testing.T) {
	got := ComputeInputHashesKey(&evaluation.InputHashes{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": "h1",
			"b.json": "h2",
		},
	})
	if got == "" {
		t.Fatal("per-file fallback must produce a non-empty key")
	}
	// Re-running with the same inputs must produce the same key.
	again := ComputeInputHashesKey(&evaluation.InputHashes{
		Files: map[evaluation.FilePath]kernel.Digest{
			"b.json": "h2",
			"a.json": "h1",
		},
	})
	if got != again {
		t.Fatal("per-file fallback must be deterministic across map orderings")
	}
}

func TestComputeChainsDigest_NoChainsIsConstant(t *testing.T) {
	if ComputeChainsDigest(nil) != ComputeChainsDigest([]policy.ChainDefinition{}) {
		t.Fatal("nil and empty chain slices should produce the same digest")
	}
}
