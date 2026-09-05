package compare

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestAnalyze_FrameworkKeyVersionAndHyphenFlexibility(t *testing.T) {
	input := Input{
		GeneratedAt:  "2026-01-01T00:00:00Z",
		BaselineName: "CIS AWS",
		TargetName:   "NIST 800-53",
		BaselineKey:  "cis_aws",     // unversioned key supplied by user
		TargetKey:    "nist-800-53", // hyphenated key supplied by user
		Findings: []remediation.Finding{
			{
				ControlID: kernel.ControlID("CTL.S3.001"),
				ControlCompliance: policy.ComplianceMapping{
					"cis_aws_v1.4.0": "1.1",
					"nist_800_53_r5": "AC-2",
				},
			},
		},
	}

	res := Analyze(input)
	if len(res.SharedViolations) != 1 {
		t.Fatalf("expected 1 shared violation for unversioned/hyphenated keys, got %d", len(res.SharedViolations))
	}
	if len(res.SharedViolations[0].Baseline) == 0 || res.SharedViolations[0].Baseline[0] != "1.1" {
		t.Errorf("expected baseline citation '1.1', got %v", res.SharedViolations[0].Baseline)
	}
	if len(res.SharedViolations[0].Target) == 0 || res.SharedViolations[0].Target[0] != "AC-2" {
		t.Errorf("expected target citation 'AC-2', got %v", res.SharedViolations[0].Target)
	}
}
