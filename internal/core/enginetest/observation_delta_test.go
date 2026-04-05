package enginetest

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestComputeObservationDelta_DetectsChanges(t *testing.T) {
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	prev := asset.Snapshot{
		CapturedAt: t1,
		Assets: []asset.Asset{
			{ID: "res-a", Type: "bucket", Properties: map[string]any{"public": false}},
			{ID: "res-b", Type: "bucket", Properties: map[string]any{"public": true}},
		},
	}
	curr := asset.Snapshot{
		CapturedAt: t2,
		Assets: []asset.Asset{
			{ID: "res-a", Type: "bucket", Properties: map[string]any{"public": true}},
			{ID: "res-c", Type: "bucket", Properties: map[string]any{"public": false}},
		},
	}

	diff := asset.ComputeDrift(prev, curr)
	if diff.Summary.Provisioned() != 1 {
		t.Errorf("Added = %d, want 1", diff.Summary.Provisioned())
	}
	if diff.Summary.Decommissioned() != 1 {
		t.Errorf("Removed = %d, want 1", diff.Summary.Decommissioned())
	}
	if diff.Summary.Reconfigured() != 1 {
		t.Errorf("Modified = %d, want 1", diff.Summary.Reconfigured())
	}
	if diff.SchemaVersion != kernel.SchemaDiff {
		t.Errorf("SchemaVersion = %q, want %q", diff.SchemaVersion, kernel.SchemaDiff)
	}
}

func TestDiffResources_DetectsPropertyChanges(t *testing.T) {
	prev := asset.Asset{
		ID:   "res-a",
		Type: "bucket",
		Properties: map[string]any{
			"public": false,
			"tags":   map[string]any{"owner": "team-a"},
		},
	}
	curr := asset.Asset{
		ID:   "res-a",
		Type: "bucket",
		Properties: map[string]any{
			"public": true,
			"tags":   map[string]any{"owner": "team-b"},
		},
	}

	changes := asset.DiffAssets(prev, curr)
	if len(changes) != 2 {
		t.Fatalf("expected 2 property changes, got %d", len(changes))
	}
}

func TestLatestTwoSnapshots(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	in := []asset.Snapshot{
		{CapturedAt: t2},
		{CapturedAt: t1},
		{CapturedAt: t3},
	}
	prev, curr, err := asset.GetStateTransition(in)
	if err != nil {
		t.Fatalf("GetStateTransition returned error: %v", err)
	}
	if !prev.CapturedAt.Equal(t2) {
		t.Errorf("prev.CapturedAt = %v, want %v", prev.CapturedAt, t2)
	}
	if !curr.CapturedAt.Equal(t3) {
		t.Errorf("curr.CapturedAt = %v, want %v", curr.CapturedAt, t3)
	}
}

func TestLatestTwoSnapshots_InsufficientSnapshots(t *testing.T) {
	in := []asset.Snapshot{{}}
	_, _, err := asset.GetStateTransition(in)
	if err == nil {
		t.Fatal("expected error for insufficient snapshots")
	}
}

func TestSummarizeDeltaChanges(t *testing.T) {
	changes := []asset.AssetChange{
		{Action: asset.DriftProvisioned},
		{Action: asset.DriftProvisioned},
		{Action: asset.DriftDecommissioned},
		{Action: asset.DriftReconfigured},
	}
	s := asset.SummarizeDrift(changes)
	if s.Provisioned() != 2 || s.Decommissioned() != 1 || s.Reconfigured() != 1 || s.Total() != 4 {
		t.Errorf("unexpected summary: %+v", s)
	}
}
