package cel

import "testing"

func TestParseAssets_SingleSnapshot(t *testing.T) {
	data := []byte(`{"assets":[{"id":"asset-1","type":"t","vendor":"v","properties":{}}]}`)
	assets, n, err := parseAssets(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("snapshot count = %d, want 1", n)
	}
	if len(assets) != 1 {
		t.Errorf("assets count = %d, want 1", len(assets))
	}
}

func TestParseAssets_MultiSnapshotBundle_FlattensAll(t *testing.T) {
	// Bundle with 3 snapshots, each containing different assets.
	// Previously parseAssets returned only the last snapshot's
	// assets — so `b-only` would survive but `a-only` and
	// `b-and-c` would be lost. With flattening every asset is
	// visible to the CEL expression.
	data := []byte(`{
		"snapshots":[
			{"assets":[{"id":"a-only","type":"t","vendor":"v","properties":{}},{"id":"b-and-c","type":"t","vendor":"v","properties":{}}]},
			{"assets":[{"id":"b-and-c","type":"t","vendor":"v","properties":{}}]},
			{"assets":[{"id":"c-only","type":"t","vendor":"v","properties":{}}]}
		]
	}`)
	assets, n, err := parseAssets(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("snapshot count = %d, want 3", n)
	}
	// Union: a-only, b-and-c (×2), c-only — 4 entries (no dedupe).
	if len(assets) != 4 {
		t.Errorf("assets count = %d, want 4 (a-only, b-and-c×2, c-only)", len(assets))
	}
	seen := map[string]bool{}
	for _, a := range assets {
		seen[string(a.ID)] = true
	}
	for _, want := range []string{"a-only", "b-and-c", "c-only"} {
		if !seen[want] {
			t.Errorf("missing asset %q from flattened union", want)
		}
	}
}

func TestParseAssets_NoAssets(t *testing.T) {
	_, _, err := parseAssets([]byte(`{"snapshots":[]}`))
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}
