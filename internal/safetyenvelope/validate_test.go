package safetyenvelope

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

func TestValidateEvaluationAndVerification(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	run := evaluation.RunInfo{
		StaveVersion:      "test",
		Offline:           true,
		Now:               now,
		MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		Snapshots:         1,
	}
	summary := evaluation.Summary{
		AssetsEvaluated: 1,
		AttackSurface:   1,
		Violations:      1,
	}
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID:          "CTL.TEST.001",
				ControlName:        "Test Control",
				ControlDescription: "test",
				AssetID:            "resource-1",
				AssetType:          kernel.AssetType("storage_bucket"),
				AssetVendor:        kernel.Vendor("aws"),
				Evidence:           evaluation.Evidence{},
			},
			RemediationSpec: policy.RemediationSpec{
				Description: "desc",
				Action:      "action",
			},
		},
	}

	eval := NewEvaluation(EvaluationRequest{
		Run:      run,
		Summary:  summary,
		Findings: findings,
	})
	if err := ValidateEvaluation(eval); err != nil {
		t.Fatalf("ValidateEvaluation() error = %v", err)
	}

	verification := NewVerification(VerificationRequest{
		Run: VerificationRunInfo{
			StaveVersion:      "test",
			Offline:           true,
			Now:               now,
			MaxUnsafeDuration: 24 * time.Hour,
			BeforeSnapshots:   1,
			AfterSnapshots:    1,
		},
		Summary: VerificationSummary{
			BeforeViolations: 1,
			AfterViolations:  0,
			Resolved:         1,
			Remaining:        0,
			Introduced:       0,
		},
	})
	if err := ValidateVerification(verification); err != nil {
		t.Fatalf("ValidateVerification() error = %v", err)
	}
}

func TestValidateDiagnose_ErrorLabel(t *testing.T) {
	err := ValidateDiagnose(&Diagnose{})
	if err == nil {
		t.Fatal("expected validation error for empty diagnose payload")
	}
	if !strings.Contains(err.Error(), "diagnose output") {
		t.Fatalf("error = %q, want diagnose output label", err.Error())
	}
}
