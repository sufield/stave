package yaml

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestTriageIndex_Resolve_OverrideOnly(t *testing.T) {
	idx := &TriageIndex{
		overrides: map[kernel.ControlID]TriageProse{
			"CTL.S3.ACCESS.001": {Defect: "d", Infection: "i", Failure: "f"},
		},
	}
	got := idx.Resolve("CTL.S3.ACCESS.001")
	if got.Defect != "d" || got.Infection != "i" || got.Failure != "f" {
		t.Errorf("expected override values, got %+v", got)
	}
}

func TestTriageIndex_Resolve_FamilyOnly(t *testing.T) {
	idx := &TriageIndex{
		overrides: map[kernel.ControlID]TriageProse{},
		families: []familyEntry{
			{prefix: "CTL.S3", prose: TriageProse{Infection: "fam-inf", Failure: "fam-fail"}},
		},
	}
	got := idx.Resolve("CTL.S3.ACCESS.001")
	if got.Infection != "fam-inf" {
		t.Errorf("infection = %q, want family value", got.Infection)
	}
	if got.Failure != "fam-fail" {
		t.Errorf("failure = %q, want family value", got.Failure)
	}
}

func TestTriageIndex_Resolve_MergesOverrideAndFamily(t *testing.T) {
	idx := &TriageIndex{
		overrides: map[kernel.ControlID]TriageProse{
			"CTL.S3.ACCESS.001": {Defect: "specific-defect"},
		},
		families: []familyEntry{
			{prefix: "CTL.S3", prose: TriageProse{Infection: "fam-inf", Failure: "fam-fail"}},
		},
	}
	got := idx.Resolve("CTL.S3.ACCESS.001")
	if got.Defect != "specific-defect" {
		t.Errorf("defect = %q, want override", got.Defect)
	}
	if got.Infection != "fam-inf" {
		t.Errorf("infection = %q, want family fallback", got.Infection)
	}
}

func TestTriageIndex_Resolve_NoMatch(t *testing.T) {
	idx := &TriageIndex{
		overrides: map[kernel.ControlID]TriageProse{},
		families:  []familyEntry{},
	}
	got := idx.Resolve("CTL.UNKNOWN.001")
	if got.Defect != "" || got.Infection != "" || got.Failure != "" {
		t.Errorf("expected empty prose for no match, got %+v", got)
	}
}

func TestTriageIndex_Resolve_LongestPrefixFirst(t *testing.T) {
	idx := &TriageIndex{
		overrides: map[kernel.ControlID]TriageProse{},
		families: []familyEntry{
			{prefix: "CTL.S3.ACCESS", prose: TriageProse{Infection: "specific"}},
			{prefix: "CTL.S3", prose: TriageProse{Infection: "general"}},
		},
	}
	got := idx.Resolve("CTL.S3.ACCESS.001")
	if got.Infection != "specific" {
		t.Errorf("infection = %q, want longest-prefix match 'specific'", got.Infection)
	}
}

func TestLoadTriageIndex_MissingDir(t *testing.T) {
	idx, err := LoadTriageIndex("/nonexistent/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != nil {
		t.Fatal("expected nil for missing triage dir")
	}
}
