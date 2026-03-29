package securityaudit

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestRecomputeSummary(t *testing.T) {
	r := &Report{
		Summary: Summary{FailOn: SeverityHigh},
		Findings: []Finding{
			{ID: "A", Severity: SeverityCritical, Status: StatusFail},
			{ID: "B", Severity: SeverityMedium, Status: StatusWarn},
			{ID: "C", Severity: SeverityLow, Status: StatusPass},
			{ID: "D", Severity: SeverityHigh, Status: StatusFail},
		},
	}
	r.RecomputeSummary()

	if r.Summary.Total != 4 {
		t.Fatalf("Total=%d, want 4", r.Summary.Total)
	}
	if r.Summary.Pass != 1 {
		t.Fatalf("Pass=%d, want 1", r.Summary.Pass)
	}
	if r.Summary.Warn != 1 {
		t.Fatalf("Warn=%d, want 1", r.Summary.Warn)
	}
	if r.Summary.Fail != 2 {
		t.Fatalf("Fail=%d, want 2", r.Summary.Fail)
	}
	if !r.Summary.Gated {
		t.Fatal("Gated should be true")
	}
	if r.Summary.GatedFindingCount != 2 {
		t.Fatalf("GatedFindingCount=%d, want 2", r.Summary.GatedFindingCount)
	}
}

func TestRecomputeSummary_NilReceiver(t *testing.T) {
	var r *Report
	r.RecomputeSummary() // Should not panic.
}

func TestRecomputeSummary_FailOnNone(t *testing.T) {
	r := &Report{
		Summary: Summary{FailOn: SeverityNone},
		Findings: []Finding{
			{ID: "A", Severity: SeverityCritical, Status: StatusFail},
		},
	}
	r.RecomputeSummary()
	if r.Summary.Gated {
		t.Fatal("FailOn=NONE should disable gating")
	}
	if r.Summary.GatedFindingCount != 0 {
		t.Fatalf("GatedFindingCount=%d, want 0", r.Summary.GatedFindingCount)
	}
}

func TestRecomputeSummary_PreservesMetadata(t *testing.T) {
	r := &Report{
		Summary: Summary{
			FailOn:            SeverityHigh,
			VulnSourceUsed:    "govulncheck",
			EvidenceFreshness: "2h",
		},
		Findings: []Finding{
			{ID: "A", Severity: SeverityHigh, Status: StatusPass},
		},
	}
	r.RecomputeSummary()
	if r.Summary.VulnSourceUsed != "govulncheck" {
		t.Fatalf("VulnSourceUsed lost after recompute")
	}
	if r.Summary.EvidenceFreshness != "2h" {
		t.Fatalf("EvidenceFreshness lost after recompute")
	}
}

func TestCloneWithFilter_NilReport(t *testing.T) {
	var r *Report
	if got := r.CloneWithFilter([]Severity{SeverityHigh}); got != nil {
		t.Fatal("nil report CloneWithFilter should return nil")
	}
}

func TestCloneWithFilter_EmptyAllowed(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{ID: "A", Severity: SeverityCritical},
		},
	}
	clone := r.CloneWithFilter(nil)
	if len(clone.Findings) != 1 {
		t.Fatalf("empty allowed should return all findings, got %d", len(clone.Findings))
	}
}

func TestCloneWithFilter_Independence(t *testing.T) {
	r := &Report{
		Summary:  Summary{FailOn: SeverityHigh},
		Findings: []Finding{{ID: "A", Severity: SeverityCritical, Status: StatusFail}},
		EvidenceIndex: []EvidenceRef{
			{ID: "ev1", Path: "/tmp/ev1"},
		},
		Controls: []ControlRef{
			{Framework: "SOC2", ControlID: "CC6.1"},
		},
	}
	clone := r.CloneWithFilter([]Severity{SeverityCritical})
	// Mutate clone's evidence index.
	clone.EvidenceIndex[0].Path = "/mutated"
	if r.EvidenceIndex[0].Path == "/mutated" {
		t.Fatal("CloneWithFilter should produce independent evidence index")
	}
}

func TestNormalize(t *testing.T) {
	r := &Report{
		SchemaVersion: kernel.Schema("securityaudit.v1"),
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Summary:       Summary{FailOn: SeverityHigh},
		Findings: []Finding{
			{ID: "B", Severity: SeverityMedium, Status: StatusWarn,
				EvidenceRefs: []string{"ev2", "ev1"},
				ControlRefs:  []ControlRef{{Framework: "SOC2", ControlID: "CC6.2"}, {Framework: "SOC2", ControlID: "CC6.1"}}},
			{ID: "A", Severity: SeverityCritical, Status: StatusFail},
		},
		EvidenceIndex: []EvidenceRef{
			{ID: "ev2"}, {ID: "ev1"},
		},
		Controls: []ControlRef{
			{Framework: "SOC2", ControlID: "CC6.2"},
			{Framework: "NIST", ControlID: "AC-2"},
		},
	}
	r.Normalize()

	// Findings should be sorted by severity desc, then status, then ID.
	if r.Findings[0].ID != "A" {
		t.Fatalf("first finding ID=%q, want A (critical)", r.Findings[0].ID)
	}
	if r.Findings[1].ID != "B" {
		t.Fatalf("second finding ID=%q, want B (medium)", r.Findings[1].ID)
	}

	// Evidence index sorted by ID.
	if r.EvidenceIndex[0].ID != "ev1" {
		t.Fatalf("first evidence ID=%q, want ev1", r.EvidenceIndex[0].ID)
	}

	// Controls sorted by framework, then control ID.
	if r.Controls[0].Framework != "NIST" {
		t.Fatalf("first control framework=%q, want NIST", r.Controls[0].Framework)
	}

	// Finding-level evidence refs sorted.
	if r.Findings[1].EvidenceRefs[0] != "ev1" {
		t.Fatalf("finding B evidence refs[0]=%q, want ev1", r.Findings[1].EvidenceRefs[0])
	}

	// Finding-level control refs sorted.
	if r.Findings[1].ControlRefs[0].ControlID != "CC6.1" {
		t.Fatalf("finding B control refs[0]=%q, want CC6.1", r.Findings[1].ControlRefs[0].ControlID)
	}

	// Summary recomputed.
	if r.Summary.Total != 2 {
		t.Fatalf("Total=%d, want 2", r.Summary.Total)
	}
}

func TestNormalize_NilReceiver(t *testing.T) {
	var r *Report
	r.Normalize() // Should not panic.
}
