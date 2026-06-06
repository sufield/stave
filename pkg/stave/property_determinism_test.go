package stave_test

import (
	"bytes"
	"testing"

	"pgregory.net/rapid"
)

// TestProperty_ApplyIsDeterministic asserts Stave's core determinism guarantee:
// the same observations + the same control catalog must produce byte-identical
// assessments across repeated runs.
//
// Why a violation matters: Stave is sold as a reproducible proof system — a
// run's verdict must depend only on its inputs, never on hidden state. The two
// Apply calls below share an isolated-but-ENABLED content-addressed cache, so
// the first call is a cache MISS (compute + persist) and the second is a cache
// HIT (replay). Any divergence means the cache (or any output-layer transform)
// is not state-preserving — exactly the class of bug where a cache round-trip
// silently changes the emitted output.
func TestProperty_ApplyIsDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("property test: drives the full Apply pipeline over many generated inputs; skipped under -short")
	}
	// Isolated cache dir, shared across iterations (each fixture hashes to a
	// distinct key, so there is no cross-iteration collision). Cache stays
	// ENABLED so each iteration exercises miss-then-hit.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	rapid.Check(t, func(rt *rapid.T) {
		snaps := genSnapshots(rt)
		cfg, cleanup := writePropFixture(t, snaps)
		defer cleanup()

		first := canonicalJSON(rt, applyOrFatal(rt, cfg))  // cache MISS
		second := canonicalJSON(rt, applyOrFatal(rt, cfg)) // cache HIT

		if !bytes.Equal(first, second) {
			rt.Fatalf("Apply is non-deterministic across repeated runs (cache miss vs hit diverged).\n"+
				"first  (miss): %s\nsecond (hit):  %s", first, second)
		}
	})
}
