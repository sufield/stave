package hygiene

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

func TestToStatuses_ValidValues(t *testing.T) {
	raw := []string{"overdue", "DUE_NOW", " upcoming "}
	got := toStatuses(raw)
	if len(got) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(got))
	}
	if got[0] != risk.StatusOverdue {
		t.Fatalf("got[0] = %q, want OVERDUE", got[0])
	}
	if got[1] != risk.StatusDueNow {
		t.Fatalf("got[1] = %q, want DUE_NOW", got[1])
	}
	if got[2] != risk.StatusUpcoming {
		t.Fatalf("got[2] = %q, want UPCOMING", got[2])
	}
}

func TestToStatuses_InvalidValues(t *testing.T) {
	raw := []string{"invalid", "EXPIRED", "unknown"}
	got := toStatuses(raw)
	if len(got) != 0 {
		t.Fatalf("expected 0 statuses for invalid values, got %d: %v", len(got), got)
	}
}

func TestToStatuses_EmptyStrings(t *testing.T) {
	raw := []string{"", "  ", "\t"}
	got := toStatuses(raw)
	if len(got) != 0 {
		t.Fatalf("expected 0 statuses for empty strings, got %d", len(got))
	}
}

func TestToStatuses_Mixed(t *testing.T) {
	raw := []string{"overdue", "invalid", "", "upcoming"}
	got := toStatuses(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 valid statuses, got %d: %v", len(got), got)
	}
}

func TestToStatuses_Nil(t *testing.T) {
	got := toStatuses(nil)
	if len(got) != 0 {
		t.Fatalf("expected 0 statuses for nil, got %d", len(got))
	}
}

func TestIsValidStatus(t *testing.T) {
	tests := []struct {
		status risk.ThresholdStatus
		valid  bool
	}{
		{risk.StatusOverdue, true},
		{risk.StatusDueNow, true},
		{risk.StatusUpcoming, true},
		{"INVALID", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isValidStatus(tt.status)
		if got != tt.valid {
			t.Errorf("isValidStatus(%q) = %v, want %v", tt.status, got, tt.valid)
		}
	}
}

func TestFilterSnapshotsBefore_AllBefore(t *testing.T) {
	cutoff := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: cutoff.Add(-5 * time.Hour)},
		{CapturedAt: cutoff.Add(-1 * time.Hour)},
		{CapturedAt: cutoff.Add(-10 * time.Hour)},
	}
	got := filterSnapshotsBefore(snapshots, cutoff)
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	// Should be sorted chronologically
	for i := 1; i < len(got); i++ {
		if got[i].CapturedAt.Before(got[i-1].CapturedAt) {
			t.Fatal("expected ascending order")
		}
	}
}

func TestFilterSnapshotsBefore_NoneMatch(t *testing.T) {
	cutoff := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: cutoff.Add(1 * time.Hour)},
		{CapturedAt: cutoff.Add(5 * time.Hour)},
	}
	got := filterSnapshotsBefore(snapshots, cutoff)
	if len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestFilterSnapshotsBefore_ExactCutoff(t *testing.T) {
	cutoff := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: cutoff}, // exactly at cutoff — should be included
	}
	got := filterSnapshotsBefore(snapshots, cutoff)
	if len(got) != 1 {
		t.Fatalf("expected 1 (exact cutoff included), got %d", len(got))
	}
}

func TestFilterSnapshotsBefore_Empty(t *testing.T) {
	cutoff := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	got := filterSnapshotsBefore(nil, cutoff)
	if len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestParseDueWithin_Empty(t *testing.T) {
	d, err := parseDueWithin("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 0 {
		t.Fatalf("expected 0 for empty, got %v", d)
	}
}

func TestParseDueWithin_Valid(t *testing.T) {
	d, err := parseDueWithin("24h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 24*time.Hour {
		t.Fatalf("expected 24h, got %v", d)
	}
}

func TestParseDueWithin_Invalid(t *testing.T) {
	_, err := parseDueWithin("bad")
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestUpcomingFilter_DueWithinPtr_Zero(t *testing.T) {
	f := UpcomingFilter{}
	if f.DueWithinPtr() != nil {
		t.Fatal("expected nil for zero DueWithin")
	}
}

func TestUpcomingFilter_DueWithinPtr_Positive(t *testing.T) {
	f := UpcomingFilter{DueWithin: 24 * time.Hour}
	p := f.DueWithinPtr()
	if p == nil {
		t.Fatal("expected non-nil for positive DueWithin")
	}
	if *p != 24*time.Hour {
		t.Fatalf("expected 24h, got %v", *p)
	}
}

func TestUpcomingFilter_DueWithinPtr_Negative(t *testing.T) {
	f := UpcomingFilter{DueWithin: -1 * time.Hour}
	if f.DueWithinPtr() != nil {
		t.Fatal("expected nil for negative DueWithin")
	}
}
