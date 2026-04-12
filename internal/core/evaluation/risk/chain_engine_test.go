package risk

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestDetectChains(t *testing.T) {
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

	ctlPublic := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
	}
	ctlEncrypt := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{"attack_stage": "exfiltration"}),
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.S3.PUBLIC.001":  ctlPublic,
		"CTL.S3.ENCRYPT.001": ctlEncrypt,
	}

	t.Run("two controls trigger chain", func(t *testing.T) {
		failing := map[kernel.ControlID]bool{
			"CTL.S3.PUBLIC.001":  true,
			"CTL.S3.ENCRYPT.001": true,
		}
		findings := DetectChains(failing, chains, lookup)
		if len(findings) != 1 {
			t.Fatalf("expected 1 compound finding, got %d", len(findings))
		}
		f := findings[0]
		if f.ChainID != "phi_exposure" {
			t.Errorf("ChainID = %q, want phi_exposure", f.ChainID)
		}
		if len(f.ControlsFailing) != 2 {
			t.Errorf("ControlsFailing = %d, want 2", len(f.ControlsFailing))
		}
		// MissingSafeguards = controls in chain that are NOT failing
		if len(f.MissingSafeguards) != 1 {
			t.Errorf("MissingSafeguards = %d, want 1 (CTL.S3.LOG.001 is still holding)", len(f.MissingSafeguards))
		}
		if f.Severity != policy.SeverityCritical {
			t.Errorf("Severity = %v, want CRITICAL", f.Severity)
		}
		if f.CompoundScore <= 0 {
			t.Errorf("CompoundScore = %f, want > 0", f.CompoundScore)
		}
		if len(f.AttackStages) != 2 {
			t.Errorf("AttackStages = %v, want 2 stages", f.AttackStages)
		}
	})

	t.Run("below threshold no finding", func(t *testing.T) {
		failing := map[kernel.ControlID]bool{
			"CTL.S3.PUBLIC.001": true,
		}
		findings := DetectChains(failing, chains, lookup)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings below threshold, got %d", len(findings))
		}
	})

	t.Run("no failing controls", func(t *testing.T) {
		findings := DetectChains(map[kernel.ControlID]bool{}, chains, lookup)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("multiple chains can fire", func(t *testing.T) {
		failing := map[kernel.ControlID]bool{
			"CTL.S3.PUBLIC.001":          true,
			"CTL.S3.ENCRYPT.001":         true,
			"CTL.IAM.ROOT.MFA.001":       true,
			"CTL.IAM.ROOT.ACCESSKEY.001": true,
		}
		findings := DetectChains(failing, chains, lookup)
		if len(findings) != 2 {
			t.Errorf("expected 2 compound findings, got %d", len(findings))
		}
	})

	t.Run("blast multiplier affects score", func(t *testing.T) {
		blastCtl := &policy.ControlDefinition{
			Params: policy.NewParams(map[string]any{
				"attack_stage": "detection_evasion",
				"blast_radius": map[string]any{
					"type":       "detection",
					"scope":      "account",
					"multiplier": float64(2.5),
				},
			}),
		}
		detectionChain := []policy.ChainDefinition{{
			ID:                  "blind",
			Description:         "Detection disabled",
			ControlIDs:          []kernel.ControlID{"CTL.CLOUDTRAIL.001", "CTL.GUARDDUTY.001"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
		}}
		detectionLookup := map[kernel.ControlID]*policy.ControlDefinition{
			"CTL.CLOUDTRAIL.001": blastCtl,
			"CTL.GUARDDUTY.001":  blastCtl,
		}
		failing := map[kernel.ControlID]bool{
			"CTL.CLOUDTRAIL.001": true,
			"CTL.GUARDDUTY.001":  true,
		}
		findings := DetectChains(failing, detectionChain, detectionLookup)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		// With account-scoped blast multiplier 2.5: score = 10 * 1.8 * 2.5 = 45.0
		if findings[0].CompoundScore < 40.0 {
			t.Errorf("CompoundScore = %f, expected >= 40 with blast multiplier", findings[0].CompoundScore)
		}
	})

	t.Run("scope attenuation reduces multiplier", func(t *testing.T) {
		// Resource-scoped blast (S3 logging) should be attenuated.
		resourceCtl := &policy.ControlDefinition{
			Params: policy.NewParams(map[string]any{
				"blast_radius": map[string]any{
					"type":       "detection",
					"scope":      "resource",
					"multiplier": float64(2.0),
				},
			}),
		}
		// Account-scoped (CloudTrail) should NOT be attenuated.
		accountCtl := &policy.ControlDefinition{
			Params: policy.NewParams(map[string]any{
				"blast_radius": map[string]any{
					"type":       "detection",
					"scope":      "account",
					"multiplier": float64(2.0),
				},
			}),
		}

		chain := []policy.ChainDefinition{{
			ID:                  "scope_test",
			ControlIDs:          []kernel.ControlID{"A", "B"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityHigh,
		}}

		// Resource-scoped: effective = 1.0 + (2.0-1.0)*0.50 = 1.5
		resourceFindings := DetectChains(
			map[kernel.ControlID]bool{"A": true, "B": true},
			chain,
			map[kernel.ControlID]*policy.ControlDefinition{"A": resourceCtl, "B": resourceCtl},
		)

		// Account-scoped: effective = 2.0 (no attenuation)
		accountFindings := DetectChains(
			map[kernel.ControlID]bool{"A": true, "B": true},
			chain,
			map[kernel.ControlID]*policy.ControlDefinition{"A": accountCtl, "B": accountCtl},
		)

		if len(resourceFindings) != 1 || len(accountFindings) != 1 {
			t.Fatal("expected 1 finding each")
		}

		// Account-scoped score should be higher than resource-scoped.
		if accountFindings[0].CompoundScore <= resourceFindings[0].CompoundScore {
			t.Errorf("account score (%f) should be > resource score (%f)",
				accountFindings[0].CompoundScore, resourceFindings[0].CompoundScore)
		}
		t.Logf("account=%f resource=%f",
			accountFindings[0].CompoundScore, resourceFindings[0].CompoundScore)
	})
}
