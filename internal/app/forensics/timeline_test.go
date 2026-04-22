package forensics

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func TestBuildTimeline_PropertyChange(t *testing.T) {
	snap1 := asset.Snapshot{
		CapturedAt: time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			{ID: "arn:aws:s3:::bucket", Properties: map[string]any{
				"storage": map[string]any{"public": false},
			}},
		},
	}
	snap2 := asset.Snapshot{
		CapturedAt: time.Date(2025, 11, 2, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			{ID: "arn:aws:s3:::bucket", Properties: map[string]any{
				"storage": map[string]any{"public": true},
			}},
		},
	}

	tl, err := BuildTimeline(Input{
		AssetID:   "arn:aws:s3:::bucket",
		Snapshots: []asset.Snapshot{snap1, snap2},
	})
	if err != nil {
		t.Fatal(err)
	}

	if tl.SnapshotsAnalyzed != 2 {
		t.Errorf("snapshots = %d, want 2", tl.SnapshotsAnalyzed)
	}

	// Should have first_seen + property change.
	propChanges := 0
	for _, ev := range tl.Events {
		if ev.EventType == "property_change" {
			propChanges++
			if ev.Property != "storage.public" {
				t.Errorf("property = %q, want storage.public", ev.Property)
			}
		}
	}
	if propChanges != 1 {
		t.Errorf("property changes = %d, want 1", propChanges)
	}
}

func TestBuildTimeline_AssetDisappears(t *testing.T) {
	snap1 := asset.Snapshot{
		CapturedAt: time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			{ID: "arn:aws:s3:::bucket", Properties: map[string]any{}},
		},
	}
	snap2 := asset.Snapshot{
		CapturedAt: time.Date(2025, 11, 2, 0, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{}, // asset gone
	}

	tl, err := BuildTimeline(Input{
		AssetID:   "arn:aws:s3:::bucket",
		Snapshots: []asset.Snapshot{snap1, snap2},
	})
	if err != nil {
		t.Fatal(err)
	}

	hasLastSeen := false
	for _, ev := range tl.Events {
		if ev.EventType == "last_seen" {
			hasLastSeen = true
		}
	}
	if !hasLastSeen {
		t.Error("expected last_seen event when asset disappears")
	}
}

func TestBuildTimeline_EmptySnapshots(t *testing.T) {
	_, err := BuildTimeline(Input{AssetID: "arn:test"})
	if err == nil {
		t.Error("expected error for no snapshots")
	}
}

func TestDiffProperties(t *testing.T) {
	prev := map[string]any{"a": 1, "b": "old", "c": true}
	curr := map[string]any{"a": 1, "b": "new", "d": "added"}

	deltas := diffProperties("", prev, curr)

	// b changed, c removed, d added = 3 deltas.
	if len(deltas) != 3 {
		t.Errorf("deltas = %d, want 3", len(deltas))
		for _, d := range deltas {
			t.Logf("  %s: %v → %v", d.path, d.from, d.to)
		}
	}
}

func TestExposureWindowComputation(t *testing.T) {
	events := []Event{
		{Timestamp: "2025-11-01T00:00:00Z", EventType: "control_verdict_change",
			ControlID: "CTL.A", To: "fail"},
		{Timestamp: "2025-11-05T00:00:00Z", EventType: "control_verdict_change",
			ControlID: "CTL.A", To: "pass"},
	}

	windows := computeExposureWindows(events)
	if len(windows) != 1 {
		t.Fatalf("windows = %d, want 1", len(windows))
	}
	if windows[0].Status != "remediated" {
		t.Errorf("status = %q, want remediated", windows[0].Status)
	}
	if windows[0].ExposureDays != 4 {
		t.Errorf("days = %f, want 4", windows[0].ExposureDays)
	}
}

func TestExposureWindowMalformedTimestamp(t *testing.T) {
	events := []Event{
		{Timestamp: "not-a-timestamp", EventType: "control_verdict_change",
			ControlID: "CTL.A", To: "fail"},
		{Timestamp: "also-invalid", EventType: "control_verdict_change",
			ControlID: "CTL.A", To: "pass"},
	}

	windows := computeExposureWindows(events)
	if len(windows) != 1 {
		t.Fatalf("windows = %d, want 1", len(windows))
	}
	if windows[0].ExposureDays != -1 {
		t.Errorf("days = %f, want -1 for malformed timestamps", windows[0].ExposureDays)
	}
}
