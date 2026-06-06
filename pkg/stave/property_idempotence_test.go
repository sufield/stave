package stave_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"pgregory.net/rapid"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
)

// reparse marshals each snapshot to obs.v0.1 JSON and parses it straight back
// through the production loader (schema validation + type normalization). A
// load failure on a generated, well-formed snapshot is a property failure.
func reparse(rt *rapid.T, snaps []asset.Snapshot) []asset.Snapshot {
	loader := observations.NewObservationLoader()
	out := make([]asset.Snapshot, len(snaps))
	for i, s := range snaps {
		b, err := json.Marshal(s)
		if err != nil {
			rt.Fatalf("marshal snapshot %d: %v", i, err)
		}
		got, err := loader.LoadSnapshotFromReader(context.Background(), bytes.NewReader(b), "roundtrip")
		if err != nil {
			rt.Fatalf("re-parse of a serialized snapshot failed (round-trip is not closed): %v\njson: %s", err, b)
		}
		out[i] = got
	}
	return out
}

// TestProperty_ObservationRoundTripIsStable asserts the export→parse→export
// stability that Phase-0 settled on, since Stave exposes no fact RE-importer:
// once a snapshot has been serialized and parsed, serializing and parsing it
// AGAIN must not change it. The loaded snapshot is the exact value every
// downstream consumer reads — the evaluation engine, and the SIR/SMT-LIB fact
// export fed to external reasoning engines — so a non-idempotent round-trip
// means the on-disk observation and the in-memory model disagree, and the
// facts exported to Z3 would describe a slightly different account than the
// stored evidence.
//
// The first parse may legitimately normalize (coerce types, fill defaults); the
// property pins the FIXED POINT: parse∘serialize applied to an already-parsed
// snapshot is the identity.
func TestProperty_ObservationRoundTripIsStable(t *testing.T) {
	if testing.Short() {
		t.Skip("property test: exercises the parse/serialize round-trip over many generated inputs; skipped under -short")
	}
	rapid.Check(t, func(rt *rapid.T) {
		snaps := genSnapshots(rt)

		once := reparse(rt, snaps) // first normalization
		twice := reparse(rt, once) // must be a fixed point from here

		b1, err := json.Marshal(once)
		if err != nil {
			rt.Fatalf("marshal once: %v", err)
		}
		b2, err := json.Marshal(twice)
		if err != nil {
			rt.Fatalf("marshal twice: %v", err)
		}
		if !bytes.Equal(b1, b2) {
			rt.Fatalf("observation round-trip is not a fixed point — re-parsing a parsed snapshot changed it:\n"+
				"once:  %s\ntwice: %s", b1, b2)
		}
	})
}
