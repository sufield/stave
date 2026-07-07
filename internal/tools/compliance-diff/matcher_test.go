package main

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func testMatcher(controls ...policy.ControlDefinition) *matcher {
	return newMatcher(policy.NewCatalog(controls))
}

func testControl(id, name, desc string, tags ...string) policy.ControlDefinition {
	var scopeTags []kernel.ScopeTag
	for _, t := range tags {
		scopeTags = append(scopeTags, kernel.ScopeTag(t))
	}
	return policy.ControlDefinition{
		ID:          kernel.ControlID(id),
		Name:        name,
		Description: desc,
		ScopeTags:   scopeTags,
	}
}

func TestMatch_RuntimeScope_ReturnsOutOfScope(t *testing.T) {
	m := testMatcher()
	result := m.match(compliance.Check{
		ID:      "T-1",
		Service: "CloudWatch",
		Scope:   "runtime",
	})
	if result.Status != "out_of_scope" {
		t.Errorf("status = %q, want out_of_scope", result.Status)
	}
}

func TestMatch_ProcessScope_ReturnsOutOfScope(t *testing.T) {
	m := testMatcher()
	result := m.match(compliance.Check{
		ID:      "T-1",
		Service: "IAM",
		Scope:   "process",
	})
	if result.Status != "out_of_scope" {
		t.Errorf("status = %q, want out_of_scope", result.Status)
	}
}

func TestMatch_ExactPropertyMatch_ReturnsCovered(t *testing.T) {
	m := testMatcher(
		testControl("CTL.S3.ENCRYPT.001", "S3 default encryption", "Ensure S3 bucket default encryption is enabled", "s3"),
	)
	result := m.match(compliance.Check{
		ID:          "CIS-2.1.1",
		Service:     "S3",
		Property:    "default encryption",
		Description: "S3 bucket default encryption is enabled",
	})
	if result.Status != "covered" {
		t.Errorf("status = %q, want covered", result.Status)
	}
	if len(result.ControlIDs) == 0 {
		t.Error("expected at least one control ID")
	}
}

func TestMatch_NoMatch_ReturnsGap(t *testing.T) {
	m := testMatcher(
		testControl("CTL.S3.ENCRYPT.001", "S3 encryption", "encryption controls", "s3"),
	)
	result := m.match(compliance.Check{
		ID:          "T-1",
		Service:     "S3",
		Description: "completely unrelated widget frobulation",
	})
	if result.Status != "gap" {
		t.Errorf("status = %q, want gap", result.Status)
	}
}

func TestMatch_ZeroServiceControls_ReturnsGapWithNote(t *testing.T) {
	m := testMatcher()
	result := m.match(compliance.Check{
		ID:          "T-1",
		Service:     "SomeNewService",
		Description: "something",
	})
	if result.Status != "gap" {
		t.Errorf("status = %q, want gap", result.Status)
	}
	if result.Notes == "" {
		t.Error("expected a note about zero controls")
	}
}

func TestExtractKeywords(t *testing.T) {
	kw := extractKeywords("Ensure MFA is enabled for the root user account")
	if len(kw) == 0 {
		t.Fatal("expected keywords")
	}
	hasRoot := false
	for _, k := range kw {
		if k == "root" {
			hasRoot = true
		}
	}
	if !hasRoot {
		t.Error("expected 'root' in keywords")
	}
}

func TestDiffReport_ComputeSummary(t *testing.T) {
	r := DiffReport{
		Results: []MatchResult{
			{Status: "covered"},
			{Status: "covered"},
			{Status: "partial"},
			{Status: "gap"},
			{Status: "out_of_scope"},
		},
	}
	r.computeSummary()

	if r.Summary.Total != 5 {
		t.Errorf("total = %d, want 5", r.Summary.Total)
	}
	if r.Summary.InScope != 4 {
		t.Errorf("in_scope = %d, want 4", r.Summary.InScope)
	}
	if r.Summary.Covered != 2 {
		t.Errorf("covered = %d, want 2", r.Summary.Covered)
	}
	if r.Summary.Partial != 1 {
		t.Errorf("partial = %d, want 1", r.Summary.Partial)
	}
	if r.Summary.Gap != 1 {
		t.Errorf("gap = %d, want 1", r.Summary.Gap)
	}
	if r.Summary.OutOfScope != 1 {
		t.Errorf("out_of_scope = %d, want 1", r.Summary.OutOfScope)
	}
}
