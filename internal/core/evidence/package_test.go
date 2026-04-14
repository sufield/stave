package evidence

import (
	"testing"
	"time"
)

func TestNewEvidencePackage(t *testing.T) {
	ts := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	pkg := NewEvidencePackage("snap-001", ts)

	if pkg.SnapshotID != "snap-001" {
		t.Errorf("SnapshotID = %q, want %q", pkg.SnapshotID, "snap-001")
	}
	if !pkg.AssessedAt.Equal(ts) {
		t.Errorf("AssessedAt = %v, want %v", pkg.AssessedAt, ts)
	}
	if pkg.TotalRecords() != 0 {
		t.Errorf("TotalRecords = %d, want 0", pkg.TotalRecords())
	}
}

func TestEvidencePackage_Add_CountsVerdicts(t *testing.T) {
	pkg := NewEvidencePackage("snap-001", time.Now())

	pkg.Add(&EvidenceRecord{Verdict: VerdictPass})
	pkg.Add(&EvidenceRecord{Verdict: VerdictPass})
	pkg.Add(&EvidenceRecord{Verdict: VerdictFail})
	pkg.Add(&EvidenceRecord{Verdict: VerdictIncomplete})
	pkg.Add(&EvidenceRecord{Verdict: VerdictNotApplicable})

	if pkg.PassCount != 2 {
		t.Errorf("PassCount = %d, want 2", pkg.PassCount)
	}
	if pkg.FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", pkg.FailCount)
	}
	if pkg.IncompleteCount != 1 {
		t.Errorf("IncompleteCount = %d, want 1", pkg.IncompleteCount)
	}
	if pkg.TotalRecords() != 5 {
		t.Errorf("TotalRecords = %d, want 5", pkg.TotalRecords())
	}
}

func TestFindByControlID_Matches(t *testing.T) {
	pkg := NewEvidencePackage("snap", time.Now())
	pkg.Add(&EvidenceRecord{ControlID: "CTL.A", ResourceARN: "arn:1"})
	pkg.Add(&EvidenceRecord{ControlID: "CTL.B", ResourceARN: "arn:2"})
	pkg.Add(&EvidenceRecord{ControlID: "CTL.A", ResourceARN: "arn:3"})

	got := pkg.FindByControlID("CTL.A")
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}

func TestFindByControlID_NoMatch(t *testing.T) {
	pkg := NewEvidencePackage("snap", time.Now())
	pkg.Add(&EvidenceRecord{ControlID: "CTL.A"})

	got := pkg.FindByControlID("CTL.MISSING")
	if got != nil {
		t.Errorf("expected nil for no match, got %v", got)
	}
}

func TestFindByControlID_EmptyPackage(t *testing.T) {
	pkg := NewEvidencePackage("snap", time.Now())
	got := pkg.FindByControlID("CTL.A")
	if got != nil {
		t.Errorf("expected nil for empty package, got %v", got)
	}
}
