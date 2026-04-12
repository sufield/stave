package risk

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuildAttackStageSummary(t *testing.T) {
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.S3.PUBLIC.001": {
			Severity: policy.SeverityCritical,
			Params:   policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
		},
		"CTL.S3.ENCRYPT.001": {
			Severity: policy.SeverityHigh,
			Params:   policy.NewParams(map[string]any{"attack_stage": "exfiltration"}),
		},
		"CTL.CLOUDTRAIL.001": {
			Severity: policy.SeverityMedium,
			Params:   policy.NewParams(map[string]any{"attack_stage": "detection_evasion"}),
		},
		"CTL.NO.STAGE": {
			Severity: policy.SeverityLow,
			Params:   policy.NewParams(nil),
		},
	}

	failing := map[kernel.ControlID]bool{
		"CTL.S3.PUBLIC.001":  true,
		"CTL.S3.ENCRYPT.001": true,
		"CTL.CLOUDTRAIL.001": true,
		"CTL.NO.STAGE":       true,
	}

	summary := BuildAttackStageSummary(failing, lookup)

	if summary["initial_access"] != "CRITICAL" {
		t.Errorf("initial_access = %q, want CRITICAL", summary["initial_access"])
	}
	if summary["exfiltration"] != "HIGH" {
		t.Errorf("exfiltration = %q, want HIGH", summary["exfiltration"])
	}
	if summary["detection_evasion"] != "MEDIUM" {
		t.Errorf("detection_evasion = %q, want MEDIUM", summary["detection_evasion"])
	}
	if summary["credential_access"] != "PASS" {
		t.Errorf("credential_access = %q, want PASS", summary["credential_access"])
	}
	if summary["persistence"] != "PASS" {
		t.Errorf("persistence = %q, want PASS", summary["persistence"])
	}
	if summary["resilience"] != "PASS" {
		t.Errorf("resilience = %q, want PASS", summary["resilience"])
	}
}

func TestBuildAttackStageSummary_Empty(t *testing.T) {
	summary := BuildAttackStageSummary(nil, nil)
	for _, stage := range AllAttackStages {
		if summary[stage] != "PASS" {
			t.Errorf("%s = %q, want PASS", stage, summary[stage])
		}
	}
}

func TestAttackStagesFromFindings(t *testing.T) {
	findings := []CompoundFinding{
		{AttackStages: []string{"exfiltration", "initial_access"}},
		{AttackStages: []string{"initial_access", "persistence"}},
	}
	stages := AttackStagesFromFindings(findings)
	if len(stages) != 3 {
		t.Fatalf("expected 3 unique stages, got %d: %v", len(stages), stages)
	}
	if stages[0] != "exfiltration" || stages[1] != "initial_access" || stages[2] != "persistence" {
		t.Errorf("stages not sorted: %v", stages)
	}
}
