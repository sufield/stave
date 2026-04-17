package catalogquality

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestAnalyze_MissingFieldDetected(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       "ctl-complete",
			Severity: policy.SeverityCritical,
			Remediation: policy.NewRemediationSpec(
				"Fix it", "run terraform apply", "",
			),
			Compliance: policy.ComplianceMapping{"hipaa": "164.312(a)"},
			Params:     policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
		},
		{
			ID:       "ctl-incomplete",
			Severity: policy.SeverityNone, // missing severity
			// no remediation, no compliance, no attack_stage
		},
	}

	report := Analyze(Input{
		Controls:   controls,
		AssetTypes: map[kernel.AssetType]int{},
	})

	if report.TotalControls != 2 {
		t.Fatalf("expected 2 controls, got %d", report.TotalControls)
	}

	// severity: 1 present (Critical), 1 missing (None)
	sev := report.Completeness["severity"]
	if sev.Present != 1 || sev.Missing != 1 {
		t.Errorf("severity: present=%d missing=%d, want 1/1", sev.Present, sev.Missing)
	}

	// remediation.action: 1 present, 1 missing
	rem := report.Completeness["remediation.action"]
	if rem.Present != 1 || rem.Missing != 1 {
		t.Errorf("remediation.action: present=%d missing=%d, want 1/1", rem.Present, rem.Missing)
	}

	if report.OverallPct >= 100 {
		t.Errorf("expected overall pct below 100, got %v", report.OverallPct)
	}
}

func TestAnalyze_BlindSpotIdentified(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       "s3-ctl",
			Domain:   "s3_bucket",
			Severity: policy.SeverityHigh,
		},
	}

	report := Analyze(Input{
		Controls: controls,
		AssetTypes: map[kernel.AssetType]int{
			"s3_bucket":       5,
			"lambda_function": 3, // no controls cover this
		},
	})

	if len(report.BlindSpots) != 1 {
		t.Fatalf("expected 1 blind spot, got %d", len(report.BlindSpots))
	}
	if report.BlindSpots[0].AssetType != "lambda_function" {
		t.Errorf("expected blind spot for lambda_function, got %q", report.BlindSpots[0].AssetType)
	}
	if report.BlindSpots[0].AssetCount != 3 {
		t.Errorf("expected 3 assets, got %d", report.BlindSpots[0].AssetCount)
	}
}
