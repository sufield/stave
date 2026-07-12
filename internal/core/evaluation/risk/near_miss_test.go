package risk

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestDetectNearMisses(t *testing.T) {
	chains := []policy.ChainDefinition{
		{
			ID:                  "phi_exposure",
			Description:         "PHI data exposed",
			ControlIDs:          []kernel.ControlID{"CTL.S3.PUBLIC.001", "CTL.S3.ENCRYPT.001", "CTL.S3.LOG.001"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
		},
		{
			ID:                  "root_path",
			Description:         "Root compromise",
			ControlIDs:          []kernel.ControlID{"CTL.IAM.ROOT.MFA.001", "CTL.IAM.ROOT.ACCESSKEY.001"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
		},
	}

	t.Run("one control failing on threshold-2 chain emits per holding control", func(t *testing.T) {
		// phi_exposure: 3 controls, threshold 2. One failing = threshold-1.
		// Two holding controls → two near-miss entries (either would complete).
		failures := failingControls("bucket-1", "CTL.S3.PUBLIC.001")
		nearMisses := DetectNearMisses(failures, chains, nil)
		var phiMisses int
		for _, nm := range nearMisses {
			if nm.ChainID == "phi_exposure" {
				phiMisses++
			}
		}
		if phiMisses != 2 {
			t.Fatalf("expected 2 phi_exposure near misses (one per holding), got %d", phiMisses)
		}
	})

	t.Run("exactly one short of threshold with one holding", func(t *testing.T) {
		// root_path has 2 controls, threshold 2. One failing = threshold - 1 = near miss
		// BUT only if len(holding) == 1 (which means total - failing == 1)
		failures := failingControls("account-1", "CTL.IAM.ROOT.MFA.001")
		nearMisses := DetectNearMisses(failures, chains, nil)

		var found bool
		for _, nm := range nearMisses {
			if nm.ChainID == "root_path" {
				found = true
				if nm.MissingControl != "CTL.IAM.ROOT.ACCESSKEY.001" {
					t.Errorf("MissingControl = %q, want CTL.IAM.ROOT.ACCESSKEY.001", nm.MissingControl)
				}
			}
		}
		if !found {
			t.Errorf("expected root_path near miss, got %v", nearMisses)
		}
	})

	t.Run("chain that fires is not a near miss", func(t *testing.T) {
		// Both controls fail → chain fires (threshold met), NOT a near miss
		failures := failingControls("account-1", "CTL.IAM.ROOT.MFA.001", "CTL.IAM.ROOT.ACCESSKEY.001")
		nearMisses := DetectNearMisses(failures, chains, nil)
		for _, nm := range nearMisses {
			if nm.ChainID == "root_path" {
				t.Error("fired chain should not appear as near miss")
			}
		}
	})

	t.Run("two controls short is not a near miss", func(t *testing.T) {
		// phi_exposure has 3 controls, threshold 2. Zero failing = 2 short, not near miss
		// (no failures at all → no near misses for phi_exposure)
		failures := failingControls("other-asset", "CTL.UNRELATED.001")
		nearMisses := DetectNearMisses(failures, chains, nil)
		for _, nm := range nearMisses {
			if nm.ChainID == "phi_exposure" {
				t.Error("chain with 2+ missing should not be near miss")
			}
		}
	})
}
