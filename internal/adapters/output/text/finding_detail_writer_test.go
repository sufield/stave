package text

import (
	"bytes"
	"strings"
	"testing"
	"time"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

func TestWriteFindingDetail_Basic(t *testing.T) {
	firstUnsafe := time.Date(2026, 1, 14, 12, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:          "CTL.S3.PUBLIC.001",
			Name:        "No Public S3 Bucket Read",
			Description: "Buckets must not allow public read access.",
			Severity:    policy.SeverityCritical,
			Domain:      "exposure",
			Type:        "unsafe_state",
			Compliance:  policy.ComplianceMapping{"cis_aws_v1.4.0": "2.1.5"},
		},
		Asset: evaluation.FindingAssetSummary{
			ID:         "res:aws:s3:bucket:test-bucket",
			Type:       "aws:s3:bucket",
			Vendor:     "aws",
			ObservedAt: lastSeen,
		},
		Evidence: evaluation.Evidence{
			FirstUnsafeAt:       firstUnsafe,
			LastSeenUnsafeAt:    lastSeen,
			UnsafeDurationHours: 12.0,
			ThresholdHours:      24.0,
			Misconfigurations: []policy.Misconfiguration{
				{Property: "properties.storage.access.public_read", ActualValue: true, Operator: predicate.OpEq, UnsafeValue: true},
			},
			RootCauses: []evaluation.RootCause{evaluation.RootCauseIdentity},
		},
		Remediation: &policy.RemediationSpec{
			Description: "Bucket is publicly exposed.",
			Action:      "Enable Block Public Access.",
			Example:     `{"public_read": false}`,
		},
		NextSteps: []string{
			"Apply the remediation action described above.",
			"Re-run `stave apply` after applying changes.",
		},
	}

	var buf bytes.Buffer
	if err := WriteFindingDetail(&buf, detail); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Check key sections
	checks := []string{
		"Diagnosis for Violation: CTL.S3.PUBLIC.001 on res:aws:s3:bucket:test-bucket",
		"Severity: Critical",
		"cis_aws_v1.4.0",
		"Control (CTL.S3.PUBLIC.001): No Public S3 Bucket Read",
		"Description: Buckets must not allow public read access.",
		"Type: unsafe_state",
		"Domain: exposure",
		"Asset: res:aws:s3:bucket:test-bucket (Type: aws:s3:bucket, Vendor: aws)",
		"Observed at: 2026-01-15T00:00:00Z",
		"First unsafe at:",
		"Unsafe duration:    12.0h",
		"Misconfigurations:",
		`property "storage.access.public_read" has unsafe value: true`,
		"Root causes:",
		"identity",
		"Remediation Guidance",
		"Enable Block Public Access.",
		"Example configuration:",
		"Next Steps",
		"Apply the remediation action",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("output missing %q\n\nFull output:\n%s", check, out)
		}
	}
}

func TestWriteFindingDetail_WithTrace(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:   "CTL.TEST.001",
			Name: "Test Control",
		},
		Asset: evaluation.FindingAssetSummary{
			ID:   "res:test",
			Type: "test:type",
		},
		Evidence: evaluation.Evidence{},
		Trace: &evaluation.FindingTrace{
			Raw: &stavecel.TraceResult{
				ControlID:  kernel.ControlID("CTL.TEST.001"),
				AssetID:    "res:test",
				Expression: `any(properties.x == true)`,
				Result:     true,
			},
			FinalResult: true,
		},
		NextSteps: []string{"Done."},
	}

	var buf bytes.Buffer
	if err := WriteFindingDetail(&buf, detail); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Predicate Evaluation Trace") {
		t.Error("missing trace section header")
	}
	if !strings.Contains(out, "properties.x") {
		t.Error("missing field path in trace")
	}
	if !strings.Contains(out, "Result:") {
		t.Error("missing Result line in trace")
	}
}

func TestWriteFindingDetail_MinimalFields(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:   "CTL.TEST.001",
			Name: "Minimal",
		},
		Asset: evaluation.FindingAssetSummary{
			ID:   "res:test",
			Type: "test:type",
		},
		Evidence:  evaluation.Evidence{},
		NextSteps: []string{"Check."},
	}

	var buf bytes.Buffer
	if err := WriteFindingDetail(&buf, detail); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CTL.TEST.001") {
		t.Error("missing control ID")
	}
	// Should not contain trace section when nil
	if strings.Contains(out, "Predicate Evaluation Trace") {
		t.Error("should not have trace section when trace is nil")
	}
	// Should not contain remediation when remediation is nil
	if strings.Contains(out, "Remediation Guidance") {
		t.Error("should not have remediation section when remediation is nil")
	}
}
