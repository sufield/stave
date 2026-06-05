package observations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzLoadSnapshotFromReader asserts the fail-loud parsing invariant: for ANY
// input bytes, LoadSnapshotFromReader must either return a non-nil error or a
// fully-formed single snapshot — never a nil error alongside a
// partially-populated snapshot, and never a panic.
//
// Why a violation matters: an empty-id or empty-type asset that slips through
// with a nil error matches no control's scope, so it is silently skipped and
// the run reports a wrong COMPLIANT verdict for a resource that was never
// actually evaluated. Both intake paths (schema-validated single-file and
// ParseBundle) reject empty id/type, so a nil error here is a hard guarantee
// of a fully-formed snapshot; this fuzz pins that guarantee against regression.
func FuzzLoadSnapshotFromReader(f *testing.F) {
	seeds := []string{
		// --- baseline / structurally invalid ---
		``,   // empty input
		`{}`, // object missing all required fields
		`[]`, // wrong top-level type
		`{`,  // truncated JSON
		`null`,
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[`, // truncated mid-array
		// --- valid single-file + valid 1-element bundle (exercise the success path) ---
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","vendor":"aws","properties":{}}]}`,
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[]}`,
		`{"schema_version":"obs.v0.1"}`,
		`{"schema_version":"obs.v0.1","snapshots":[{"captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","vendor":"aws","properties":{}}]}]}`,
		// multi-line / pretty-printed (the loader reads a whole document, not line-delimited JSON)
		"{\n  \"schema_version\": \"obs.v0.1\",\n  \"captured_at\": \"2026-01-01T00:00:00Z\",\n  \"assets\": [\n    {\"id\": \"r-1\", \"type\": \"storage_bucket\", \"vendor\": \"aws\", \"properties\": {}}\n  ]\n}",
		// --- known-tricky ---
		// deeply nested object in properties
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","properties":{"a":{"b":{"c":{"d":{"e":{"f":{}}}}}}}}]}`,
		// huge integer
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","properties":{"n":999999999999999999999999999999}}]}`,
		// duplicate keys (encoding/json keeps the last; must not panic or half-populate)
		`{"schema_version":"obs.v0.1","schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[]}`,
		// invalid UTF-8 inside a string value
		"{\"schema_version\":\"obs.v0.1\",\"captured_at\":\"2026-01-01T00:00:00Z\",\"assets\":[{\"id\":\"\xff\xfe-bad\",\"type\":\"storage_bucket\",\"properties\":{}}]}",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	loader := NewObservationLoader()

	f.Fuzz(func(t *testing.T, input string) {
		snap, err := loader.LoadSnapshotFromReader(context.Background(), strings.NewReader(input), "fuzz")
		if err != nil {
			// The error path IS the fail-loud contract: a non-nil (wrapped) error
			// and a zero Snapshot. Nothing further to assert.
			return
		}
		// err == nil: the loader claims a valid single snapshot. It must be
		// fully formed — no partially-populated assets.
		for i, a := range snap.Assets {
			if a.ID == "" {
				t.Fatalf("nil error but asset[%d] has empty ID (partially-populated snapshot leaked into the pipeline); input=%q", i, input)
			}
			if a.Type == "" {
				t.Fatalf("nil error but asset[%d] (id=%s) has empty Type; input=%q", i, a.ID, input)
			}
		}
		// A successfully-parsed snapshot must round-trip back to JSON (no NaN/Inf
		// or otherwise unencodable state smuggled in via numbers).
		if _, mErr := json.Marshal(snap); mErr != nil {
			t.Fatalf("nil error but parsed snapshot does not re-marshal: %v; input=%q", mErr, input)
		}
	})
}

// FuzzParseBundle asserts the same fail-loud invariant for the multi-snapshot
// bundle intake path: arbitrary bytes must yield either a non-nil error or a
// slice of fully-formed snapshots — each with a non-zero CapturedAt and every
// asset carrying a non-empty ID and validated Type — never a nil error with a
// malformed snapshot, never a panic.
//
// Why a violation matters: the bundle path deliberately skips the obs.v0.1 JSON
// schema (bundle entries omit schema_version), so its hand-rolled shape checks
// are the only thing keeping bundle and single-file intake in agreement. A gap
// here lets a malformed asset load only via bundles, producing a verdict that
// silently differs from the directory/stdin path on byte-identical resources.
func FuzzParseBundle(f *testing.F) {
	seeds := []string{
		``, `{}`, `[]`, `{`, `null`,
		`{"snapshots":[]}`,              // empty snapshots array -> error
		`{"snapshots":[{"assets":[]}]}`, // snapshot missing captured_at -> error
		// valid single- and multi-snapshot bundles (exercise the success path)
		`{"schema_version":"obs.v0.1","snapshots":[{"captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","vendor":"aws","properties":{}}]}]}`,
		`{"schema_version":"obs.v0.1","snapshots":[{"captured_at":"2026-01-01T00:00:00Z","assets":[]},{"captured_at":"2026-01-02T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","properties":{}}]}]}`,
		// per-field rejections the shape checks must enforce
		`{"snapshots":[{"captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"","type":"storage_bucket","properties":{}}]}]}`, // empty id
		`{"snapshots":[{"captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"","properties":{}}]}]}`,            // empty type
		`{"snapshots":[{"captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"BAD TYPE!","properties":{}}]}]}`,   // malformed type
		// known-tricky
		`{"snapshots":[{"captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","properties":{"a":{"b":{"c":{"d":{}}}}}}]}]}`,
		"{\"snapshots\":[{\"captured_at\":\"2026-01-01T00:00:00Z\",\"assets\":[{\"id\":\"\xff\xfe-bad\",\"type\":\"storage_bucket\",\"properties\":{}}]}]}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		snaps, err := ParseBundle(data)
		if err != nil {
			return // error path is the fail-loud contract
		}
		if len(snaps) == 0 {
			t.Fatalf("nil error but ParseBundle returned zero snapshots; input=%q", data)
		}
		for si := range snaps {
			snap := snaps[si]
			if snap.CapturedAt.IsZero() {
				t.Fatalf("nil error but snapshot[%d] has zero CapturedAt; input=%q", si, data)
			}
			for ai, a := range snap.Assets {
				if a.ID == "" {
					t.Fatalf("nil error but snapshot[%d].asset[%d] has empty ID; input=%q", si, ai, data)
				}
				if a.Type == "" {
					t.Fatalf("nil error but snapshot[%d].asset[%d] (id=%s) has empty Type; input=%q", si, ai, a.ID, data)
				}
			}
			if _, mErr := json.Marshal(snap); mErr != nil {
				t.Fatalf("nil error but snapshot[%d] does not re-marshal: %v; input=%q", si, mErr, data)
			}
		}
	})
}
