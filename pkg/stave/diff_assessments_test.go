package stave_test

import (
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

func TestDiffAssessments_AddedAndRemoved(t *testing.T) {
	prev := &stave.Assessment{
		Status: stave.StatusNonCompliant,
		Findings: []stave.Finding{
			{FindingID: "sha256:aaa", ControlID: "CTL.A", AssetID: "asset-1", Severity: "high"},
			{FindingID: "sha256:bbb", ControlID: "CTL.B", AssetID: "asset-2", Severity: "medium"},
		},
	}
	curr := &stave.Assessment{
		Status: stave.StatusNonCompliant,
		Findings: []stave.Finding{
			{FindingID: "sha256:bbb", ControlID: "CTL.B", AssetID: "asset-2", Severity: "medium"},
			{FindingID: "sha256:ccc", ControlID: "CTL.C", AssetID: "asset-3", Severity: "critical"},
		},
	}

	diff := stave.DiffAssessments(prev, curr)

	if len(diff.Added) != 1 || diff.Added[0].FindingID != "sha256:ccc" {
		t.Errorf("Added = %v, want [sha256:ccc]", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].FindingID != "sha256:aaa" {
		t.Errorf("Removed = %v, want [sha256:aaa]", diff.Removed)
	}
	if len(diff.Unchanged) != 1 || diff.Unchanged[0].FindingID != "sha256:bbb" {
		t.Errorf("Unchanged = %v, want [sha256:bbb]", diff.Unchanged)
	}
}

func TestDiffAssessments_SeverityChanged(t *testing.T) {
	prev := &stave.Assessment{
		Findings: []stave.Finding{
			{FindingID: "sha256:aaa", Severity: "medium"},
		},
	}
	curr := &stave.Assessment{
		Findings: []stave.Finding{
			{FindingID: "sha256:aaa", Severity: "critical"},
		},
	}

	diff := stave.DiffAssessments(prev, curr)

	if len(diff.SeverityChanged) != 1 {
		t.Fatalf("SeverityChanged = %d, want 1", len(diff.SeverityChanged))
	}
	if diff.SeverityChanged[0].PreviousSeverity != "medium" {
		t.Errorf("PreviousSeverity = %s, want medium", diff.SeverityChanged[0].PreviousSeverity)
	}
	if diff.SeverityChanged[0].Finding.Severity != "critical" {
		t.Errorf("Finding.Severity = %s, want critical", diff.SeverityChanged[0].Finding.Severity)
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Unchanged) != 0 {
		t.Error("severity change should not appear in Added/Removed/Unchanged")
	}
}

func TestDiffAssessments_IdenticalAssessments(t *testing.T) {
	a := &stave.Assessment{
		Status: stave.StatusCompliant,
		Findings: []stave.Finding{
			{FindingID: "sha256:aaa"},
			{FindingID: "sha256:bbb"},
		},
	}

	diff := stave.DiffAssessments(a, a)

	if len(diff.Added) != 0 {
		t.Errorf("Added = %d, want 0", len(diff.Added))
	}
	if len(diff.Removed) != 0 {
		t.Errorf("Removed = %d, want 0", len(diff.Removed))
	}
	if len(diff.Unchanged) != 2 {
		t.Errorf("Unchanged = %d, want 2", len(diff.Unchanged))
	}
}

func TestDiffAssessments_EmptyPrevious(t *testing.T) {
	prev := &stave.Assessment{}
	curr := &stave.Assessment{
		Findings: []stave.Finding{
			{FindingID: "sha256:aaa"},
		},
	}

	diff := stave.DiffAssessments(prev, curr)

	if len(diff.Added) != 1 {
		t.Errorf("Added = %d, want 1", len(diff.Added))
	}
	if len(diff.Removed) != 0 {
		t.Errorf("Removed = %d, want 0", len(diff.Removed))
	}
}
