package coverage_test

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/coverage"
)

func TestBuildCoverageIndex_EmptyControls(t *testing.T) {
	idx := coverage.BuildCoverageIndex(nil, nil)
	if len(idx.ByTool) != 0 {
		t.Fatalf("expected empty index, got %d tools", len(idx.ByTool))
	}
}

func TestBuildCoverageIndex_ControlsWithoutAlternatives(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.STAVE.UNIQUE.001"},
		{ID: "CTL.STAVE.UNIQUE.002"},
	}

	idx := coverage.BuildCoverageIndex(controls, nil)

	if len(idx.ByTool) != 0 {
		t.Fatalf("expected empty index when no alternatives present, got %d tools", len(idx.ByTool))
	}
}

func TestBuildCoverageIndex_SingleToolNoInventory(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{
			ID: "CTL.S3.OWNERSHIP.001",
			Alternatives: []controldef.Alternative{
				{Tool: "tool-a", CheckID: "check-1", Coverage: controldef.CoverageCovered},
			},
		},
	}

	idx := coverage.BuildCoverageIndex(controls, nil)

	domains, ok := idx.ByTool["tool-a"]
	if !ok {
		t.Fatalf("expected tool-a in index, got %v", idx.ByTool)
	}
	dc, ok := domains["_unmatched"]
	if !ok {
		t.Fatalf("expected _unmatched domain, got %v", domains)
	}
	if dc.Covered != 1 {
		t.Errorf("Covered = %d, want 1", dc.Covered)
	}
	if dc.Total != 0 {
		t.Errorf("Total = %d, want 0 (no inventory)", dc.Total)
	}
	if dc.NotCoveredChecks != nil {
		t.Errorf("NotCoveredChecks = %v, want nil (no inventory)", dc.NotCoveredChecks)
	}
}

func TestBuildCoverageIndex_MultipleToolsBucketByTool(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{
			ID: "CTL.S3.A.001",
			Alternatives: []controldef.Alternative{
				{Tool: "tool-a", CheckID: "a1", Coverage: controldef.CoverageCovered},
				{Tool: "tool-b", CheckID: "b1", Coverage: controldef.CoverageCovered},
			},
		},
		{
			ID: "CTL.S3.A.002",
			Alternatives: []controldef.Alternative{
				{Tool: "tool-b", CheckID: "b2", Coverage: controldef.CoveragePartial},
			},
		},
	}

	idx := coverage.BuildCoverageIndex(controls, nil)

	if len(idx.ByTool) != 2 {
		t.Fatalf("expected 2 tools, got %d (%v)", len(idx.ByTool), idx.ByTool)
	}
	if got := idx.ByTool["tool-a"]["_unmatched"].Covered; got != 1 {
		t.Errorf("tool-a covered = %d, want 1", got)
	}
	if got := idx.ByTool["tool-b"]["_unmatched"].Covered; got != 2 {
		t.Errorf("tool-b covered = %d, want 2", got)
	}
}

func TestBuildCoverageIndex_InventoryResolvesDomainAndTotals(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{
			ID: "CTL.S3.A.001",
			Alternatives: []controldef.Alternative{
				{Tool: "tool-a", CheckID: "s3_one", Coverage: controldef.CoverageCovered},
			},
		},
		{
			ID: "CTL.IAM.A.001",
			Alternatives: []controldef.Alternative{
				{Tool: "tool-a", CheckID: "iam_one", Coverage: controldef.CoverageCovered},
			},
		},
	}
	inventories := []coverage.ToolInventory{
		{Tool: "tool-a", Domain: "s3", Checks: []string{"s3_one", "s3_two", "s3_three"}},
		{Tool: "tool-a", Domain: "iam", Checks: []string{"iam_one", "iam_two"}},
	}

	idx := coverage.BuildCoverageIndex(controls, inventories)

	s3 := idx.ByTool["tool-a"]["s3"]
	if s3.Covered != 1 {
		t.Errorf("s3 Covered = %d, want 1", s3.Covered)
	}
	if s3.Total != 3 {
		t.Errorf("s3 Total = %d, want 3", s3.Total)
	}
	if !reflect.DeepEqual(s3.NotCoveredChecks, []string{"s3_three", "s3_two"}) {
		t.Errorf("s3 NotCoveredChecks = %v, want [s3_three s3_two] (sorted)", s3.NotCoveredChecks)
	}

	iam := idx.ByTool["tool-a"]["iam"]
	if iam.Covered != 1 {
		t.Errorf("iam Covered = %d, want 1", iam.Covered)
	}
	if iam.Total != 2 {
		t.Errorf("iam Total = %d, want 2", iam.Total)
	}
	if !reflect.DeepEqual(iam.NotCoveredChecks, []string{"iam_two"}) {
		t.Errorf("iam NotCoveredChecks = %v, want [iam_two]", iam.NotCoveredChecks)
	}
}

func TestBuildCoverageIndex_InventoryForOneToolNotAnother(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{
			ID: "CTL.X.001",
			Alternatives: []controldef.Alternative{
				{Tool: "tool-a", CheckID: "a1", Coverage: controldef.CoverageCovered},
				{Tool: "tool-b", CheckID: "b1", Coverage: controldef.CoverageCovered},
			},
		},
	}
	inventories := []coverage.ToolInventory{
		{Tool: "tool-a", Domain: "s3", Checks: []string{"a1", "a2"}},
	}

	idx := coverage.BuildCoverageIndex(controls, inventories)

	a := idx.ByTool["tool-a"]["s3"]
	if a.Covered != 1 || a.Total != 2 || len(a.NotCoveredChecks) != 1 {
		t.Errorf("tool-a coverage unexpected: %+v", a)
	}

	b := idx.ByTool["tool-b"]["_unmatched"]
	if b.Covered != 1 {
		t.Errorf("tool-b covered = %d, want 1", b.Covered)
	}
	if b.Total != 0 {
		t.Errorf("tool-b Total = %d, want 0 (no inventory)", b.Total)
	}
	if b.NotCoveredChecks != nil {
		t.Errorf("tool-b NotCoveredChecks = %v, want nil", b.NotCoveredChecks)
	}
}

func TestBuildCoverageIndex_InventoryWithoutDeclaredCoverage(t *testing.T) {
	inventories := []coverage.ToolInventory{
		{Tool: "tool-a", Domain: "s3", Checks: []string{"a1", "a2"}},
	}

	idx := coverage.BuildCoverageIndex(nil, inventories)

	dc := idx.ByTool["tool-a"]["s3"]
	if dc.Covered != 0 {
		t.Errorf("Covered = %d, want 0", dc.Covered)
	}
	if dc.Total != 2 {
		t.Errorf("Total = %d, want 2", dc.Total)
	}
	if !reflect.DeepEqual(dc.NotCoveredChecks, []string{"a1", "a2"}) {
		t.Errorf("NotCoveredChecks = %v, want all entries", dc.NotCoveredChecks)
	}
}

func TestBuildCoverageIndex_DistinctCheckIDsCountedOnce(t *testing.T) {
	// 26 controls all annotate the same single check_id. Headline count
	// must be 1 (distinct check_ids covered), not 26.
	controls := make([]controldef.ControlDefinition, 26)
	for i := range controls {
		controls[i] = controldef.ControlDefinition{
			Alternatives: []controldef.Alternative{
				{Tool: "tool-a", CheckID: "shared_check", Coverage: controldef.CoverageCovered},
			},
		}
	}
	inventories := []coverage.ToolInventory{
		{Tool: "tool-a", Domain: "iam", Checks: []string{"shared_check", "other_check"}},
	}

	idx := coverage.BuildCoverageIndex(controls, inventories)

	dc := idx.ByTool["tool-a"]["iam"]
	if dc.Covered != 1 {
		t.Errorf("Covered = %d, want 1 (distinct check_ids only)", dc.Covered)
	}
	if dc.Total != 2 {
		t.Errorf("Total = %d, want 2", dc.Total)
	}
	if !reflect.DeepEqual(dc.NotCoveredChecks, []string{"other_check"}) {
		t.Errorf("NotCoveredChecks = %v, want [other_check]", dc.NotCoveredChecks)
	}
}

func TestBuildCoverageIndex_PartialCountsAsCovered(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{
			Alternatives: []controldef.Alternative{
				{Tool: "tool-a", CheckID: "c1", Coverage: controldef.CoveragePartial},
			},
		},
	}
	inventories := []coverage.ToolInventory{
		{Tool: "tool-a", Domain: "s3", Checks: []string{"c1", "c2"}},
	}

	idx := coverage.BuildCoverageIndex(controls, inventories)

	dc := idx.ByTool["tool-a"]["s3"]
	if dc.Covered != 1 {
		t.Errorf("Covered = %d, want 1 (partial counts as covered for headline)", dc.Covered)
	}
	if !reflect.DeepEqual(dc.NotCoveredChecks, []string{"c2"}) {
		t.Errorf("NotCoveredChecks = %v, want [c2]", dc.NotCoveredChecks)
	}
}

func TestBuildCoverageIndex_NoOpaqueToolNamePatterns(t *testing.T) {
	// Architecture invariant: core never pattern-matches on tool names.
	// Any string the test invents must work identically.
	controls := []controldef.ControlDefinition{
		{
			Alternatives: []controldef.Alternative{
				{Tool: "made-up-tool-name-1234", CheckID: "x1", Coverage: controldef.CoverageCovered},
			},
		},
	}
	inventories := []coverage.ToolInventory{
		{Tool: "made-up-tool-name-1234", Domain: "fake-domain", Checks: []string{"x1"}},
	}

	idx := coverage.BuildCoverageIndex(controls, inventories)
	if idx.ByTool["made-up-tool-name-1234"]["fake-domain"].Covered != 1 {
		t.Errorf("aggregation must treat tool names as opaque strings")
	}
}

func TestCoverageIndex_ToolNames(t *testing.T) {
	idx := coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"prowler": {"s3": {Covered: 5, Total: 10}},
			"awscli":  {"iam": {Covered: 3, Total: 5}},
		},
	}
	names := idx.ToolNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(names))
	}
	if names[0] != "awscli" || names[1] != "prowler" {
		t.Errorf("expected sorted [awscli, prowler], got %v", names)
	}
}

func TestCoverageIndex_ToolNames_Empty(t *testing.T) {
	idx := coverage.CoverageIndex{}
	names := idx.ToolNames()
	if len(names) != 0 {
		t.Errorf("expected 0 tools for empty index, got %d", len(names))
	}
}

func TestCoverageIndex_DomainsForTool(t *testing.T) {
	idx := coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"prowler": {
				"s3":  {Covered: 5, Total: 10},
				"iam": {Covered: 3, Total: 5},
			},
		},
	}
	domains := idx.DomainsForTool("prowler")
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	if domains[0] != "iam" || domains[1] != "s3" {
		t.Errorf("expected sorted [iam, s3], got %v", domains)
	}
}

func TestCoverageIndex_DomainsForTool_Unknown(t *testing.T) {
	idx := coverage.CoverageIndex{ByTool: map[string]map[string]coverage.DomainCoverage{}}
	domains := idx.DomainsForTool("nonexistent")
	if domains == nil {
		t.Fatal("expected non-nil empty slice for unknown tool")
	}
	if len(domains) != 0 {
		t.Errorf("expected 0 domains, got %d", len(domains))
	}
}

func TestBuildCoverageIndex_DuplicateChecksInInventory(t *testing.T) {
	inventories := []coverage.ToolInventory{
		{Tool: "tool-a", Domain: "s3", Checks: []string{"check-1", "check-1", "check-2"}},
	}

	idx := coverage.BuildCoverageIndex(nil, inventories)

	s3 := idx.ByTool["tool-a"]["s3"]
	if s3.Total != 2 {
		t.Errorf("expected total unique checks to be 2, got %d", s3.Total)
	}
	expectedNotCovered := []string{"check-1", "check-2"}
	if !reflect.DeepEqual(s3.NotCoveredChecks, expectedNotCovered) {
		t.Errorf("expected unique NotCoveredChecks %v, got %v", expectedNotCovered, s3.NotCoveredChecks)
	}
}
