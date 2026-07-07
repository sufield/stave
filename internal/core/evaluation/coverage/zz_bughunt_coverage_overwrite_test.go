package coverage

import (
	"testing"
)

func TestBugHunt_BuildCoverageIndex_MergesSameToolDomainInventories(t *testing.T) {
	// Two inventories for the same tool and domain, with different checks
	inventories := []ToolInventory{
		{
			Tool:   "tool-1",
			Domain: "domain-1",
			Checks: []string{"check-1"},
		},
		{
			Tool:   "tool-1",
			Domain: "domain-1",
			Checks: []string{"check-2"},
		},
	}

	idx := BuildCoverageIndex(nil, inventories)

	domains, ok := idx.ByTool["tool-1"]
	if !ok {
		t.Fatalf("expected tool-1 to be present in index")
	}

	dc, ok := domains["domain-1"]
	if !ok {
		t.Fatalf("expected domain-1 to be present for tool-1")
	}

	// We expect Total to be 2 (check-1 + check-2).
	// Under the buggy code: it overwrites the domain coverage, resulting in Total=1.
	if dc.Total != 2 {
		t.Errorf("expected Total checks to be 2, got %d (overwritten/not merged)", dc.Total)
	}

	if len(dc.NotCoveredChecks) != 2 {
		t.Errorf("expected 2 uncovered checks, got %d: %+v", len(dc.NotCoveredChecks), dc.NotCoveredChecks)
	}
}
