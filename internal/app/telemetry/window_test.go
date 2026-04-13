package telemetry

import (
	"testing"
	"time"
)

func t1() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
func t2() time.Time { return time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC) }
func t3() time.Time { return time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC) }

func TestWindowTracker_NewWindow(t *testing.T) {
	tracker := NewWindowTracker()
	wid := tracker.Track("bucket-a", "CTL.S3.001", t1())
	if wid != "bucket-a/CTL.S3.001/2026-01-01T00:00:00Z" {
		t.Fatalf("unexpected window_id: %s", wid)
	}
}

func TestWindowTracker_WindowPersists(t *testing.T) {
	tracker := NewWindowTracker()
	wid1 := tracker.Track("bucket-a", "CTL.S3.001", t1())
	wid2 := tracker.Track("bucket-a", "CTL.S3.001", t2())
	if wid1 != wid2 {
		t.Fatalf("consecutive violations should share window_id: %s != %s", wid1, wid2)
	}
}

func TestWindowTracker_WindowCloses(t *testing.T) {
	tracker := NewWindowTracker()
	tracker.Track("bucket-a", "CTL.S3.001", t1())

	// Assessment at t2 has no finding for this pair → window closes.
	closed := tracker.CloseAbsent(map[string]bool{})
	if len(closed) != 1 {
		t.Fatalf("expected 1 closed window, got %d", len(closed))
	}
}

func TestWindowTracker_WindowReopens(t *testing.T) {
	tracker := NewWindowTracker()
	wid1 := tracker.Track("bucket-a", "CTL.S3.001", t1())

	// Close it.
	tracker.CloseAbsent(map[string]bool{})

	// New violation at t3 — should get a new window_id.
	wid2 := tracker.Track("bucket-a", "CTL.S3.001", t3())
	if wid1 == wid2 {
		t.Fatalf("reopened window should have new window_id: %s == %s", wid1, wid2)
	}
	if wid2 != "bucket-a/CTL.S3.001/2026-01-03T00:00:00Z" {
		t.Fatalf("unexpected reopened window_id: %s", wid2)
	}
}
