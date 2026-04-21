package stave

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/coverage"
)

func TestFindingsForAsset(t *testing.T) {
	a := &Assessment{Findings: []Finding{
		{FindingID: "f1", AssetID: "bucket-a", ControlID: "CTL.S3.PUBLIC.001"},
		{FindingID: "f2", AssetID: "bucket-b", ControlID: "CTL.S3.PUBLIC.001"},
		{FindingID: "f3", AssetID: "bucket-a", ControlID: "CTL.S3.PAB.001"},
	}}

	got := a.FindingsForAsset("bucket-a")
	if len(got) != 2 {
		t.Fatalf("FindingsForAsset(bucket-a): want 2 findings, got %d", len(got))
	}
	if got[0].FindingID != "f1" || got[1].FindingID != "f3" {
		t.Errorf("unexpected findings: %v", got)
	}

	if mismatch := a.FindingsForAsset("bucket-missing"); len(mismatch) != 0 {
		t.Errorf("missing asset: want empty slice, got %d findings", len(mismatch))
	}
}

func TestFindingsForAssetReturnsDefensiveCopy(t *testing.T) {
	a := &Assessment{Findings: []Finding{
		{FindingID: "f1", AssetID: "bucket-a"},
	}}
	got := a.FindingsForAsset("bucket-a")
	got[0].FindingID = "mutated"
	if a.Findings[0].FindingID != "f1" {
		t.Errorf("mutation leaked to Assessment: got %q", a.Findings[0].FindingID)
	}
}

func TestConsolidatedAndSingletonIssues(t *testing.T) {
	a := &Assessment{Issues: []Issue{
		{IssueID: "i1", MemberFindingIDs: []FindingID{"f1"}},
		{IssueID: "i2", MemberFindingIDs: []FindingID{"f2", "f3"}},
		{IssueID: "i3", MemberFindingIDs: []FindingID{"f4", "f5", "f6"}},
		{IssueID: "i4", MemberFindingIDs: []FindingID{"f7"}},
	}}

	consolidated := a.ConsolidatedIssues()
	if len(consolidated) != 2 {
		t.Fatalf("ConsolidatedIssues: want 2, got %d", len(consolidated))
	}
	if consolidated[0].IssueID != "i2" || consolidated[1].IssueID != "i3" {
		t.Errorf("unexpected consolidated: %v", consolidated)
	}

	singletons := a.SingletonIssues()
	if len(singletons) != 2 {
		t.Fatalf("SingletonIssues: want 2, got %d", len(singletons))
	}
	if singletons[0].IssueID != "i1" || singletons[1].IssueID != "i4" {
		t.Errorf("unexpected singletons: %v", singletons)
	}

	// Empty assessment.
	empty := &Assessment{}
	if got := empty.ConsolidatedIssues(); len(got) != 0 {
		t.Errorf("empty ConsolidatedIssues: want 0, got %d", len(got))
	}
	if got := empty.SingletonIssues(); len(got) != 0 {
		t.Errorf("empty SingletonIssues: want 0, got %d", len(got))
	}
}

func TestIssueIsConsolidated(t *testing.T) {
	if (Issue{MemberFindingIDs: []FindingID{"f1"}}).IsConsolidated() {
		t.Error("singleton should not be consolidated")
	}
	if !(Issue{MemberFindingIDs: []FindingID{"f1", "f2"}}).IsConsolidated() {
		t.Error("two-member should be consolidated")
	}
	if (Issue{}).IsConsolidated() {
		t.Error("empty should not be consolidated")
	}
}

func TestFindingsBySeverity(t *testing.T) {
	a := &Assessment{Findings: []Finding{
		{FindingID: "f1", Severity: SeverityCritical},
		{FindingID: "f2", Severity: SeverityCritical},
		{FindingID: "f3", Severity: SeverityHigh},
		{FindingID: "f4", Severity: SeverityMedium},
		{FindingID: "f5", Severity: ""}, // skipped
		{FindingID: "f6", Severity: SeverityLow},
		{FindingID: "f7", Severity: SeverityInfo},
	}}

	got := a.FindingsBySeverity()

	// All five severities present.
	for _, sev := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if _, ok := got[sev]; !ok {
			t.Errorf("FindingsBySeverity missing severity key %q", sev)
		}
	}

	if len(got[SeverityCritical]) != 2 {
		t.Errorf("critical bucket: want 2, got %d", len(got[SeverityCritical]))
	}
	if got[SeverityCritical][0].FindingID != "f1" || got[SeverityCritical][1].FindingID != "f2" {
		t.Errorf("critical bucket order: preserves Assessment order, got %v", got[SeverityCritical])
	}
	if len(got[SeverityHigh]) != 1 || got[SeverityHigh][0].FindingID != "f3" {
		t.Errorf("high bucket: %v", got[SeverityHigh])
	}
	if len(got[SeverityMedium]) != 1 || got[SeverityMedium][0].FindingID != "f4" {
		t.Errorf("medium bucket: %v", got[SeverityMedium])
	}
	if len(got[SeverityLow]) != 1 || got[SeverityLow][0].FindingID != "f6" {
		t.Errorf("low bucket: %v", got[SeverityLow])
	}
	if len(got[SeverityInfo]) != 1 || got[SeverityInfo][0].FindingID != "f7" {
		t.Errorf("info bucket: %v", got[SeverityInfo])
	}

	// Empty-severity finding not placed in any bucket.
	for sev, findings := range got {
		for _, f := range findings {
			if f.FindingID == "f5" {
				t.Errorf("empty-severity finding ended up in bucket %q", sev)
			}
		}
	}
}

func TestFindingsBySeverityEmptyAssessment(t *testing.T) {
	got := (&Assessment{}).FindingsBySeverity()
	for _, sev := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if got[sev] == nil {
			t.Errorf("empty Assessment: bucket %q should be empty non-nil slice, got nil", sev)
		}
		if len(got[sev]) != 0 {
			t.Errorf("empty Assessment: bucket %q should be empty, got %d findings", sev, len(got[sev]))
		}
	}
}

func TestFindingsBySeverityReturnsDefensiveCopy(t *testing.T) {
	a := &Assessment{Findings: []Finding{
		{FindingID: "f1", Severity: SeverityHigh},
	}}
	got := a.FindingsBySeverity()
	got[SeverityHigh][0].FindingID = "mutated"
	if a.Findings[0].FindingID != "f1" {
		t.Errorf("mutation leaked to Assessment: got %q", a.Findings[0].FindingID)
	}
}

func TestCountBySeverity(t *testing.T) {
	a := &Assessment{Findings: []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: ""}, // skipped
		{Severity: SeverityLow},
		{Severity: SeverityInfo},
	}}

	got := a.CountBySeverity()
	want := map[Severity]int{
		SeverityCritical: 2,
		SeverityHigh:     1,
		SeverityMedium:   1,
		SeverityLow:      1,
		SeverityInfo:     1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CountBySeverity: got %v, want %v", got, want)
	}

	// All five severities present even when zero findings fire on them.
	empty := (&Assessment{}).CountBySeverity()
	for _, sev := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if _, ok := empty[sev]; !ok {
			t.Errorf("empty assessment missing severity key %q", sev)
		}
	}
}

func TestFailingFindingsByFramework(t *testing.T) {
	a := &Assessment{Findings: []Finding{
		{FindingID: "f1", ControlCompliance: map[string]string{"hipaa": "164.312", "soc2": "CC6.1"}},
		{FindingID: "f2", ControlCompliance: map[string]string{"soc2": "CC6.6"}},
		{FindingID: "f3"}, // no compliance — not grouped
	}}

	got := a.FailingFindingsByFramework()
	if len(got["hipaa"]) != 1 || got["hipaa"][0].FindingID != "f1" {
		t.Errorf("hipaa group: got %v", got["hipaa"])
	}
	if len(got["soc2"]) != 2 {
		t.Errorf("soc2 group: want 2 findings, got %d", len(got["soc2"]))
	}
	if _, present := got["pci"]; present {
		t.Errorf("pci should not appear (no findings cite it)")
	}
}

func TestFindingFrameworks(t *testing.T) {
	f := Finding{ControlCompliance: map[string]string{
		"soc2":  "CC6.1",
		"hipaa": "164.312",
		"pci":   "3.4",
	}}
	got := f.Frameworks()
	want := []string{"hipaa", "pci", "soc2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Frameworks: got %v, want %v", got, want)
	}

	// Empty ControlCompliance returns empty (non-nil) slice.
	empty := Finding{}.Frameworks()
	if empty == nil {
		t.Error("empty Finding.Frameworks should return non-nil slice")
	}
	if len(empty) != 0 {
		t.Errorf("empty Finding.Frameworks: want 0 elements, got %d", len(empty))
	}
}

func TestCoverageToolNamesAndDomains(t *testing.T) {
	c := coverage.CoverageIndex{ByTool: map[string]map[string]coverage.DomainCoverage{
		"prowler": {"s3": {Covered: 5, Total: 10}, "iam": {Covered: 3, Total: 8}},
		"checkov": {"s3": {Covered: 4, Total: 10}},
		"trivy":   {"network": {Covered: 2, Total: 5}},
	}}

	tools := c.ToolNames()
	wantTools := []string{"checkov", "prowler", "trivy"}
	if !reflect.DeepEqual(tools, wantTools) {
		t.Errorf("ToolNames: got %v, want %v", tools, wantTools)
	}

	prowlerDomains := c.DomainsForTool("prowler")
	wantDomains := []string{"iam", "s3"}
	if !reflect.DeepEqual(prowlerDomains, wantDomains) {
		t.Errorf("DomainsForTool(prowler): got %v, want %v", prowlerDomains, wantDomains)
	}

	missing := c.DomainsForTool("nonexistent")
	if missing == nil {
		t.Error("DomainsForTool(missing) should return non-nil empty slice")
	}
	if len(missing) != 0 {
		t.Errorf("DomainsForTool(missing): want 0 elements, got %d", len(missing))
	}
}

// Compile-time check: methods on internal types are visible through
// the pkg/stave aliases.
var _ = func() {
	var iss Issue
	_ = iss.IsConsolidated()

	var c CoveragePosture
	_ = c.ToolNames()
	_ = c.DomainsForTool("x")

	var _ evaluation.Issue = iss
}
