package eval

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestAnnotateChainMembership_SingleChain(t *testing.T) {
	report := &evaluation.ComplianceReport{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.A"},
			{ControlID: "CTL.B"},
			{ControlID: "CTL.C"},
		},
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:         "test_chain",
				Description:     "Test chain fires",
				ControlsFailing: []kernel.ControlID{"CTL.A", "CTL.B"},
				Severity:        policy.SeverityCritical,
				AttackStages:    []kernel.AttackStage{"exfiltration", "initial_access"},
			},
		},
	}

	annotateChainMembership(report)

	// CTL.A should be a member.
	if got := report.Findings[0].ChainMembershipCount(); got != 1 {
		t.Fatalf("CTL.A: expected 1 chain membership, got %d", got)
	}
	cm := report.Findings[0].ChainMembership[0]
	if cm.ChainID != "test_chain" {
		t.Errorf("ChainID = %q, want test_chain", cm.ChainID)
	}
	if cm.ChainSeverity != policy.SeverityCritical {
		t.Errorf("ChainSeverity = %v, want critical", cm.ChainSeverity)
	}
	// StageSpan should be sorted by kill chain order.
	if len(cm.StageSpan) != 2 || cm.StageSpan[0] != "initial_access" || cm.StageSpan[1] != "exfiltration" {
		t.Errorf("StageSpan = %v, want [initial_access exfiltration]", cm.StageSpan)
	}

	// CTL.B should be a member.
	if got := report.Findings[1].ChainMembershipCount(); got != 1 {
		t.Fatalf("CTL.B: expected 1 chain membership, got %d", got)
	}

	// CTL.C should NOT be a member.
	if got := report.Findings[2].ChainMembershipCount(); got != 0 {
		t.Errorf("CTL.C: expected 0 chain membership, got %d", got)
	}
}

func TestAnnotateChainMembership_MultipleChains(t *testing.T) {
	report := &evaluation.ComplianceReport{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.SHARED"},
			{ControlID: "CTL.ONLY_A"},
		},
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:         "chain_a",
				Description:     "Chain A",
				ControlsFailing: []kernel.ControlID{"CTL.SHARED", "CTL.ONLY_A"},
				Severity:        policy.SeverityCritical,
				AttackStages:    []kernel.AttackStage{"initial_access"},
			},
			{
				ChainID:         "chain_b",
				Description:     "Chain B",
				ControlsFailing: []kernel.ControlID{"CTL.SHARED"},
				Severity:        policy.SeverityHigh,
				AttackStages:    []kernel.AttackStage{"exfiltration"},
			},
		},
	}

	annotateChainMembership(report)

	// CTL.SHARED should be in both chains.
	if got := report.Findings[0].ChainMembershipCount(); got != 2 {
		t.Fatalf("CTL.SHARED: expected 2 chain memberships, got %d", got)
	}
	if report.Findings[0].ChainMembership[0].ChainID != "chain_a" {
		t.Errorf("first membership = %q, want chain_a", report.Findings[0].ChainMembership[0].ChainID)
	}
	if report.Findings[0].ChainMembership[1].ChainID != "chain_b" {
		t.Errorf("second membership = %q, want chain_b", report.Findings[0].ChainMembership[1].ChainID)
	}

	// CTL.ONLY_A should be in one chain.
	if got := report.Findings[1].ChainMembershipCount(); got != 1 {
		t.Fatalf("CTL.ONLY_A: expected 1 chain membership, got %d", got)
	}
}

func TestAnnotateChainMembership_NoChains(t *testing.T) {
	report := &evaluation.ComplianceReport{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.A"},
		},
	}

	annotateChainMembership(report)

	if got := report.Findings[0].ChainMembershipCount(); got != 0 {
		t.Errorf("expected no chain membership, got %d", got)
	}
}

// TestAnnotateChainMembership_BelowThreshold confirms that findings
// whose controls belong to a chain definition receive no annotation
// when the chain did not fire (below escalation threshold → not in
// ChainFindings). Only fired chains appear in ChainFindings; the
// annotation logic processes only that list.
func TestAnnotateChainMembership_BelowThreshold(t *testing.T) {
	report := &evaluation.ComplianceReport{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.A"},
			{ControlID: "CTL.B"},
		},
		// ChainFindings is empty — the chain engine determined
		// that the escalation threshold was not met.
		ChainFindings: nil,
	}

	annotateChainMembership(report)

	for i, f := range report.Findings {
		if len(f.ChainMembership) != 0 {
			t.Errorf("Finding[%d] (%s): expected 0 chain membership when chain below threshold, got %d",
				i, f.ControlID, len(f.ChainMembership))
		}
	}
}
