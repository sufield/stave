package compliancemapping

import "testing"

func mappingWith(controls ...MappedControl) *Mapping {
	return &Mapping{
		Framework: "TEST",
		Domains:   []Domain{{Domain: "D", Controls: controls}},
	}
}

func TestVerify_CleanMapping(t *testing.T) {
	m := mappingWith(
		MappedControl{ID: "IAM-01", Coverage: coverageFull, StaveControls: []string{"CTL.A", "CTL.B"}},
		MappedControl{ID: "IAM-02", Coverage: coveragePartial, StaveControls: []string{"CTL.A"}, UncoveredAspects: "periodic review is organizational"},
	)
	r := m.Verify(map[string]bool{"CTL.A": true, "CTL.B": true})
	if r.HasErrors() || r.HasWarnings() {
		t.Fatalf("clean mapping reported issues: %+v", r)
	}
	if r.ReferencedControl != 2 {
		t.Errorf("referenced = %d, want 2", r.ReferencedControl)
	}
}

func TestVerify_DanglingReference(t *testing.T) {
	m := mappingWith(MappedControl{ID: "IAM-01", Coverage: coverageFull, StaveControls: []string{"CTL.A", "CTL.GONE"}})
	r := m.Verify(map[string]bool{"CTL.A": true})
	if !r.HasErrors() {
		t.Fatal("expected error for dangling reference")
	}
	if len(r.DanglingRefs) != 1 || r.DanglingRefs[0].StaveControl != "CTL.GONE" {
		t.Fatalf("dangling = %+v, want CTL.GONE", r.DanglingRefs)
	}
}

func TestVerify_EmptyCatalogSkipsDanglingCheck(t *testing.T) {
	// A failed catalog load must NOT flag every reference as dangling.
	m := mappingWith(MappedControl{ID: "IAM-01", Coverage: coverageFull, StaveControls: []string{"CTL.A"}})
	r := m.Verify(map[string]bool{})
	if r.HasErrors() {
		t.Fatalf("empty catalog should skip dangling check, got %+v", r.DanglingRefs)
	}
}

func TestVerify_DuplicateID(t *testing.T) {
	m := mappingWith(
		MappedControl{ID: "IAM-01", Coverage: coverageNone},
		MappedControl{ID: "IAM-01", Coverage: coverageNone},
	)
	r := m.Verify(map[string]bool{})
	if !r.HasErrors() || len(r.DuplicateIDs) != 1 || r.DuplicateIDs[0] != "IAM-01" {
		t.Fatalf("duplicate = %+v, want [IAM-01]", r.DuplicateIDs)
	}
}

func TestVerify_InvalidConfidence(t *testing.T) {
	m := mappingWith(MappedControl{ID: "IAM-01", Coverage: coverageFull, StaveControls: []string{"CTL.A"}, Confidence: "maybe"})
	r := m.Verify(map[string]bool{"CTL.A": true})
	if !r.HasErrors() || len(r.InvalidConfidence) != 1 || r.InvalidConfidence[0].Value != "maybe" {
		t.Fatalf("invalid confidence = %+v", r.InvalidConfidence)
	}
}

func TestVerify_ValidConfidenceAccepted(t *testing.T) {
	for _, c := range []string{ConfidenceDirect, ConfidenceInferred, ""} {
		m := mappingWith(MappedControl{ID: "IAM-01", Coverage: coverageFull, StaveControls: []string{"CTL.A"}, Confidence: c})
		if r := m.Verify(map[string]bool{"CTL.A": true}); len(r.InvalidConfidence) != 0 {
			t.Errorf("confidence %q flagged as invalid", c)
		}
	}
}

func TestVerify_PartialWithoutReasonIsWarning(t *testing.T) {
	m := mappingWith(MappedControl{ID: "IAM-01", Coverage: coveragePartial, StaveControls: []string{"CTL.A"}})
	r := m.Verify(map[string]bool{"CTL.A": true})
	if r.HasErrors() {
		t.Fatal("partial-without-reason must be a warning, not an error")
	}
	if !r.HasWarnings() || len(r.PartialNoReason) != 1 || r.PartialNoReason[0] != "IAM-01" {
		t.Fatalf("partialNoReason = %+v, want [IAM-01]", r.PartialNoReason)
	}
}

func TestConfidenceOrDefault(t *testing.T) {
	if got := (MappedControl{}).ConfidenceOrDefault(); got != ConfidenceInferred {
		t.Errorf("empty confidence default = %q, want inferred", got)
	}
	if got := (MappedControl{Confidence: ConfidenceDirect}).ConfidenceOrDefault(); got != ConfidenceDirect {
		t.Errorf("direct = %q", got)
	}
}

// Evaluate must carry confidence/uncovered into covered results, defaulting
// a missing confidence to inferred (backward compatibility).
func TestEvaluate_CarriesConfidence(t *testing.T) {
	m := mappingWith(
		MappedControl{ID: "IAM-01", Coverage: coverageFull, StaveControls: []string{"CTL.A"}, Confidence: ConfidenceDirect},
		MappedControl{ID: "IAM-02", Coverage: coveragePartial, StaveControls: []string{"CTL.B"}, UncoveredAspects: "review is organizational"},
	)
	rep := m.Evaluate(map[string]bool{})
	if len(rep.Covered) != 2 {
		t.Fatalf("covered = %d, want 2", len(rep.Covered))
	}
	if rep.Covered[0].Confidence != ConfidenceDirect {
		t.Errorf("IAM-01 confidence = %q, want direct", rep.Covered[0].Confidence)
	}
	if rep.Covered[1].Confidence != ConfidenceInferred {
		t.Errorf("IAM-02 missing confidence should default to inferred, got %q", rep.Covered[1].Confidence)
	}
	if rep.Covered[1].Uncovered != "review is organizational" {
		t.Errorf("IAM-02 uncovered = %q", rep.Covered[1].Uncovered)
	}
}
