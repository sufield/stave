package risk

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestApplyCompensatingControls_Downgrade(t *testing.T) {
	finding := &findingsdata.CompoundFinding{
		ChainID:    "test_chain",
		Confidence: "",
	}
	chain := policy.ChainDefinition{
		CompensatingControls: []policy.CompensatingControl{
			{
				ControlID: "CTL.MFA.001",
				Effect:    policy.EffectDowngrade,
				Rationale: "MFA prevents automated exploitation",
			},
		},
	}
	passing := map[kernel.ControlID]bool{"CTL.MFA.001": true}

	ApplyCompensatingControls(finding, chain, passing)

	if finding.CompensatingNote != "MFA prevents automated exploitation" {
		t.Errorf("note = %q, want rationale", finding.CompensatingNote)
	}
	if finding.Confidence != "reduced" {
		t.Errorf("confidence = %q, want reduced", finding.Confidence)
	}
}

func TestApplyCompensatingControls_Blocks(t *testing.T) {
	finding := &findingsdata.CompoundFinding{ChainID: "test_chain"}
	chain := policy.ChainDefinition{
		CompensatingControls: []policy.CompensatingControl{
			{
				ControlID: "CTL.NACL.001",
				Effect:    policy.EffectBlocks,
				Rationale: "NACL blocks ingress",
			},
		},
	}
	passing := map[kernel.ControlID]bool{"CTL.NACL.001": true}

	ApplyCompensatingControls(finding, chain, passing)

	if finding.CompensatingNote != "NACL blocks ingress" {
		t.Errorf("note = %q, want rationale", finding.CompensatingNote)
	}
}

func TestApplyCompensatingControls_NotPassing(t *testing.T) {
	finding := &findingsdata.CompoundFinding{ChainID: "test_chain"}
	chain := policy.ChainDefinition{
		CompensatingControls: []policy.CompensatingControl{
			{
				ControlID: "CTL.MFA.001",
				Effect:    policy.EffectDowngrade,
				Rationale: "MFA prevents exploitation",
			},
		},
	}
	passing := map[kernel.ControlID]bool{}

	ApplyCompensatingControls(finding, chain, passing)

	if finding.CompensatingNote != "" {
		t.Errorf("note = %q, want empty (control not passing)", finding.CompensatingNote)
	}
}

func TestApplyCompensatingControls_Empty(t *testing.T) {
	finding := &findingsdata.CompoundFinding{ChainID: "test_chain"}
	chain := policy.ChainDefinition{}
	passing := map[kernel.ControlID]bool{"CTL.MFA.001": true}

	ApplyCompensatingControls(finding, chain, passing)

	if finding.CompensatingNote != "" {
		t.Errorf("note = %q, want empty (no compensating controls declared)", finding.CompensatingNote)
	}
}
