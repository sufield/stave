package observations

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// ---------------------------------------------------------------------------
// normalizeSnapshotTypes
// ---------------------------------------------------------------------------

func TestNormalizeSnapshotTypes_NilSnapshot(t *testing.T) {
	err := normalizeSnapshotTypes(nil)
	if err != ErrNilSnapshot {
		t.Fatalf("expected ErrNilSnapshot, got %v", err)
	}
}

func TestNormalizeSnapshotTypes_MissingTimestamp(t *testing.T) {
	snap := &asset.Snapshot{}
	err := normalizeSnapshotTypes(snap)
	if err != ErrMissingTimestamp {
		t.Fatalf("expected ErrMissingTimestamp, got %v", err)
	}
}

func TestNormalizeSnapshotTypes_Valid(t *testing.T) {
	snap := &asset.Snapshot{
		CapturedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			{Properties: map[string]any{"enabled": "true"}},
		},
	}
	if err := normalizeSnapshotTypes(snap); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ParseBundle
// ---------------------------------------------------------------------------

func TestParseBundle_Valid(t *testing.T) {
	data := []byte(`{"schema_version":"bundle.v1","snapshots":[{"schema_version":"obs.v0.1","captured_at":"2026-01-15T00:00:00Z","generated_by":{"source_type":"test","tool":"test"},"assets":[]}]}`)
	snaps, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snaps))
	}
}

func TestParseBundle_InvalidJSON(t *testing.T) {
	_, err := ParseBundle([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// StdinObservationLoader
// ---------------------------------------------------------------------------

func TestNewStdinObservationLoader_Defaults(t *testing.T) {
	loader := NewStdinObservationLoader(nil, nil)
	if loader == nil {
		t.Fatal("expected non-nil loader")
	}
}

func TestStdinObservationLoader_LoadSnapshots_EmptyInput(t *testing.T) {
	loader := NewStdinObservationLoader(nil, strings.NewReader(""))
	_, err := loader.LoadSnapshots(context.Background(), "ignored")
	if err == nil {
		t.Fatal("expected error for empty stdin input")
	}
}

// ---------------------------------------------------------------------------
// ObservationLoader options
// ---------------------------------------------------------------------------

func TestWithOnProgress(t *testing.T) {
	called := false
	fn := func(_, _ int) { called = true }
	l := NewObservationLoader(WithOnProgress(fn))
	l.onProgress(1, 1)
	if !called {
		t.Fatal("progress callback not called")
	}
}

func TestWithIntegrityCheck(t *testing.T) {
	l := NewObservationLoader(WithIntegrityCheck("/manifest.json", "/key.pem"))
	if l.integrityManifestPath != "/manifest.json" {
		t.Fatalf("manifestPath = %q", l.integrityManifestPath)
	}
	if l.integrityPublicKeyPath != "/key.pem" {
		t.Fatalf("publicKeyPath = %q", l.integrityPublicKeyPath)
	}
}
