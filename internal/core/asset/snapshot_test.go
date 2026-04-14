package asset

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestSnapshots_TemporalBounds(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)

	s := Snapshots{
		{CapturedAt: t2},
		{CapturedAt: t1},
		{CapturedAt: t3},
	}
	earliest, latest := s.TemporalBounds()
	if !earliest.Equal(t1) {
		t.Errorf("earliest = %v, want %v", earliest, t1)
	}
	if !latest.Equal(t3) {
		t.Errorf("latest = %v, want %v", latest, t3)
	}
}

func TestSnapshots_TemporalBounds_Empty(t *testing.T) {
	var s Snapshots
	earliest, latest := s.TemporalBounds()
	if !earliest.IsZero() || !latest.IsZero() {
		t.Errorf("expected zero times for empty snapshots, got earliest=%v latest=%v", earliest, latest)
	}
}

func TestSnapshots_UniqueAssetCount(t *testing.T) {
	s := Snapshots{
		{Assets: []Asset{{ID: "a"}, {ID: "b"}}},
		{Assets: []Asset{{ID: "b"}, {ID: "c"}}},
	}
	if got := s.UniqueAssetCount(); got != 3 {
		t.Errorf("UniqueAssetCount() = %d, want 3", got)
	}
}

func TestSnapshots_UniqueAssetCount_Empty(t *testing.T) {
	var s Snapshots
	if got := s.UniqueAssetCount(); got != 0 {
		t.Errorf("UniqueAssetCount() = %d, want 0", got)
	}
}

func TestSnapshot_JSONRoundTrip(t *testing.T) {
	ts := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	original := Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		GeneratedBy: &GeneratedBy{
			SourceType:   "aws-s3-snapshot",
			Tool:         "stave-extract",
			StaveVersion: "0.1.0",
			Provider:     "aws",
		},
		Source:     SourceDeployed,
		CapturedAt: ts,
		Assets: []Asset{{
			ID:     "arn:aws:s3:::my-bucket",
			Type:   "storage_bucket",
			Vendor: "aws",
			Properties: map[string]any{
				"encryption": map[string]any{"enabled": true},
			},
			Source: &SourceRef{File: "main.tf", Line: 42},
		}},
		Identities: []CloudIdentity{{
			ID:         "arn:aws:iam::123:role/admin",
			Type:       "iam_role",
			Vendor:     "aws",
			Properties: map[string]any{"admin": true},
		}},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var roundTripped Snapshot
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if roundTripped.SchemaVersion != original.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", roundTripped.SchemaVersion, original.SchemaVersion)
	}
	if roundTripped.Source != original.Source {
		t.Errorf("Source = %q, want %q", roundTripped.Source, original.Source)
	}
	if roundTripped.GeneratedBy == nil || roundTripped.GeneratedBy.SourceType != "aws-s3-snapshot" {
		t.Errorf("GeneratedBy not preserved")
	}
	if !roundTripped.CapturedAt.Equal(original.CapturedAt) {
		t.Errorf("CapturedAt = %v, want %v", roundTripped.CapturedAt, original.CapturedAt)
	}
	if len(roundTripped.Assets) != 1 || roundTripped.Assets[0].ID != "arn:aws:s3:::my-bucket" {
		t.Errorf("Assets not preserved")
	}
	if roundTripped.Assets[0].Source == nil || roundTripped.Assets[0].Source.Line != 42 {
		t.Errorf("Asset.Source not preserved")
	}
	if len(roundTripped.Identities) != 1 || roundTripped.Identities[0].ID != "arn:aws:iam::123:role/admin" {
		t.Errorf("Identities not preserved")
	}
}
