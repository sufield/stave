package inventory

import "testing"

func TestRecommendAction_KeepWithinRetentionAndQuality(t *testing.T) {
	action, _ := recommendAction(false, true, true)
	if action != "keep" {
		t.Errorf("action = %q, want keep", action)
	}
}

func TestRecommendAction_ArchivePastRetentionQualityPass(t *testing.T) {
	action, _ := recommendAction(true, true, true)
	if action != "archive" {
		t.Errorf("action = %q, want archive", action)
	}
}

func TestRecommendAction_DeletePastRetentionQualityFail(t *testing.T) {
	action, _ := recommendAction(true, false, false)
	if action != "delete" {
		t.Errorf("action = %q, want delete", action)
	}
}

func TestRecommendAction_ReviewWithinRetentionQualityFail(t *testing.T) {
	action, _ := recommendAction(false, false, true)
	if action != "review" {
		t.Errorf("action = %q, want review", action)
	}
}

func TestComputeSummary(t *testing.T) {
	snapshots := []snapshotEntry{
		{RecommendedAction: "keep", FileSizeBytes: 100},
		{RecommendedAction: "keep", FileSizeBytes: 200},
		{RecommendedAction: "archive", FileSizeBytes: 50},
		{RecommendedAction: "delete", FileSizeBytes: 10},
	}
	s := computeSummary(snapshots)
	if s.TotalFiles != 4 {
		t.Errorf("TotalFiles = %d, want 4", s.TotalFiles)
	}
	if s.RecommendedKeep != 2 {
		t.Errorf("Keep = %d, want 2", s.RecommendedKeep)
	}
	if s.RecommendedArchive != 1 {
		t.Errorf("Archive = %d, want 1", s.RecommendedArchive)
	}
	if s.RecommendedDelete != 1 {
		t.Errorf("Delete = %d, want 1", s.RecommendedDelete)
	}
	if s.TotalSizeBytes != 360 {
		t.Errorf("TotalSizeBytes = %d, want 360", s.TotalSizeBytes)
	}
}
