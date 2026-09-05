package narrative

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_BuildPlaybook_ScopesChainMembersToSameAsset(t *testing.T) {
	// Let's define a chain definition with two controls: CTL.A.001 and CTL.B.001.
	chainDefs := []policy.ChainDefinition{
		{
			ID:         kernel.ChainID("chain-1"),
			ControlIDs: []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		},
	}

	// Finding for CTL.A.001 is on asset-1.
	targetFinding := remediation.Finding{
		ControlID:       "CTL.A.001",
		AssetID:         "asset-1",
		ControlSeverity: policy.SeverityHigh,
		ChainMembership: []evaluation.ChainMembershipEntry{
			{
				ChainID:   "chain-1",
				Narrative: "Chain 1 narrative",
			},
		},
	}

	// Another finding for CTL.B.001 on asset-2 (completely different asset).
	otherFinding := remediation.Finding{
		ControlID:       "CTL.B.001",
		AssetID:         "asset-2",
		ControlSeverity: policy.SeverityHigh,
	}

	allFindings := []remediation.Finding{targetFinding, otherFinding}

	pb := BuildPlaybook(&Input{
		Finding:     targetFinding,
		ChainDefs:   chainDefs,
		AllFindings: allFindings,
	})

	if pb.Narrative.ChainContext == nil {
		t.Fatalf("expected ChainContext to be populated, got nil")
	}

	members := pb.Narrative.ChainContext.MemberControls
	if len(members) != 2 {
		t.Fatalf("expected 2 chain members, got %d", len(members))
	}

	// Member 0 (CTL.A.001) is the current finding
	if members[0].ControlID != "CTL.A.001" || members[0].Status != StatusThisFinding {
		t.Errorf("member 0 incorrect: %+v", members[0])
	}

	// Member 1 (CTL.B.001) is failing on asset-2, but NOT on asset-1.
	// Therefore, relative to asset-1, CTL.B.001 is PASSING.
	// Under the buggy code: it incorrectly marks CTL.B.001 as "also_failing" because it is failing on another asset.
	if members[1].ControlID == "CTL.B.001" && members[1].Status != StatusPassing {
		t.Errorf("expected member CTL.B.001 to have status %q, got %q (unscoped to asset-1)",
			StatusPassing, members[1].Status)
	}
}
