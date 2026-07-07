package main

import "testing"

func TestComputeDiff_FindsNewGaps(t *testing.T) {
	previous := &AuditReport{
		Quarter:     "2026-Q2",
		SingleEngine: []Gap{
			{Service: "s3", Property: "OldGap", Severity: "Medium"},
		},
	}
	current := &AuditReport{
		Quarter:     "2026-Q3",
		SingleEngine: []Gap{
			{Service: "s3", Property: "OldGap", Severity: "Medium"},
			{Service: "iam", Property: "NewGap", Severity: "High"},
		},
	}

	diff := computeDiff(current, previous)

	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if len(diff.NewGaps) != 1 {
		t.Fatalf("expected 1 new gap, got %d", len(diff.NewGaps))
	}
	if diff.NewGaps[0].Service != "iam" {
		t.Errorf("expected iam new gap, got %s", diff.NewGaps[0].Service)
	}
}

func TestComputeDiff_FindsFixedGaps(t *testing.T) {
	previous := &AuditReport{
		Quarter:     "2026-Q2",
		SingleEngine: []Gap{
			{Service: "s3", Property: "FixedGap", Severity: "Medium"},
			{Service: "ec2", Property: "StillOpen", Severity: "High"},
		},
	}
	current := &AuditReport{
		Quarter:     "2026-Q3",
		SingleEngine: []Gap{
			{Service: "ec2", Property: "StillOpen", Severity: "High"},
		},
	}

	diff := computeDiff(current, previous)

	if len(diff.FixedGaps) != 1 {
		t.Fatalf("expected 1 fixed gap, got %d", len(diff.FixedGaps))
	}
	if diff.FixedGaps[0].Service != "s3" {
		t.Errorf("expected s3 fixed gap, got %s", diff.FixedGaps[0].Service)
	}
	if len(diff.PersistentGaps) != 1 {
		t.Fatalf("expected 1 persistent gap, got %d", len(diff.PersistentGaps))
	}
}

func TestComputeDiff_NilPrevious(t *testing.T) {
	current := &AuditReport{Quarter: "2026-Q3"}
	diff := computeDiff(current, nil)
	if diff != nil {
		t.Error("expected nil diff when no previous data")
	}
}
