package simulate

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestSimulate_FindingsRemoved(t *testing.T) {
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.A.001", AssetID: asset.ID("a1")}},
		{Finding: evaluation.Finding{ControlID: "CTL.B.001", AssetID: asset.ID("a2")}},
	}
	result := Run(Input{
		Findings:     findings,
		FixControls:  []string{"CTL.A.001"},
		CurrentScore: 70,
	})
	if result.FindingsRemoved != 1 {
		t.Errorf("removed = %d, want 1", result.FindingsRemoved)
	}
	if result.ScoreDelta <= 0 {
		t.Error("score should improve when fixing findings")
	}
}

func TestSimulate_ChainDeactivation(t *testing.T) {
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.A.001"}},
		{Finding: evaluation.Finding{ControlID: "CTL.B.001"}},
	}
	chainFindings := []risk.CompoundFinding{
		{
			ChainID:         "test_chain",
			ControlsFailing: []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		},
	}
	chains := []policy.ChainDefinition{
		{
			ID:                  "test_chain",
			ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
		},
	}

	result := Run(Input{
		Findings:      findings,
		ChainFindings: chainFindings,
		Chains:        chains,
		FixControls:   []string{"CTL.A.001"},
		CurrentScore:  70,
	})

	if len(result.ChainsDeactivated) != 1 {
		t.Fatalf("deactivated chains = %d, want 1", len(result.ChainsDeactivated))
	}
	if result.ChainsDeactivated[0].ChainID != "test_chain" {
		t.Errorf("deactivated chain = %q, want test_chain", result.ChainsDeactivated[0].ChainID)
	}
}
