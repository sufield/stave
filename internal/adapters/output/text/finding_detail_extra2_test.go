package text

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// WriteFindingDetail — full exercise
// ---------------------------------------------------------------------------

func TestWriteFindingDetail_Full(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:          "CTL.A.001",
			Name:        "Public Read Access",
			Description: "S3 bucket allows public read",
			Severity:    controldef.SeverityHigh,
			Type:        "unsafe_duration",
			Domain:      "storage",
			Compliance:  controldef.ComplianceMapping{"hipaa": "164.312"},
			Exposure: &controldef.Exposure{
				Type:           "public_read",
				PrincipalScope: kernel.ScopePublic,
			},
		},
		Asset: evaluation.FindingAssetSummary{
			ID:         "bucket-1",
			Type:       "s3_bucket",
			Vendor:     "aws",
			ObservedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		},
		Evidence: evaluation.Evidence{
			FirstUnsafeAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			LastSeenUnsafeAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			UnsafeDurationHours: 336.0,
			ThresholdHours:      168.0,
			WhyNow:              "Asset has been unsafe for 336 hours",
			Misconfigurations: []controldef.Misconfiguration{
				{Property: "public_access", ActualValue: true, Operator: "eq", UnsafeValue: true},
			},
			RootCauses: []evaluation.RootCause{evaluation.RootCauseResource},
			SourceEvidence: &evaluation.SourceEvidence{
				IdentityStatements: []kernel.StatementID{"stmt-1"},
				ResourceGrantees:   []kernel.GranteeID{"AllUsers"},
			},
		},
		PostureDrift: &evaluation.PostureDrift{
			Pattern:      evaluation.DriftPersistent,
			EpisodeCount: 1,
		},
		Remediation: &controldef.RemediationSpec{
			Description: "Disable public access",
			Action:      "Set block_public_access to true",
			Example:     "{\n  \"block_public_access\": true\n}",
		},
		RemediationPlan: &evaluation.RemediationPlan{
			ID: "plan-001",
			Target: evaluation.RemediationTarget{
				AssetID:   "bucket-1",
				AssetType: "s3_bucket",
			},
			Preconditions: []string{"Verify bucket is not serving static content"},
			Actions: []evaluation.RemediationAction{
				{ActionType: evaluation.ActionSet, Path: "block_public_access", Value: true},
			},
			ExpectedEffect: "Public access will be blocked",
		},
		NextSteps: []string{"Run stave verify", "Check compliance dashboard"},
	}

	var buf bytes.Buffer
	err := WriteFindingDetail(&buf, detail)
	if err != nil {
		t.Fatalf("WriteFindingDetail: %v", err)
	}

	out := buf.String()
	expects := []string{
		"CTL.A.001",
		"bucket-1",
		"Severity: High",
		"hipaa",
		"unsafe_duration",
		"storage",
		"public_read",
		"persistent",
		"Remediation Guidance",
		"Disable public access",
		"block_public_access",
		"Fix plan",
		"Preconditions:",
		"Verify bucket",
		"Actions:",
		"Expected effect:",
		"Next Steps",
		"Run stave verify",
		"Identity statements:",
		"Resource grantees:",
		"Misconfigurations:",
		"Root causes:",
	}
	for _, exp := range expects {
		if !strings.Contains(out, exp) {
			t.Errorf("output missing %q", exp)
		}
	}
}

// ---------------------------------------------------------------------------
// WriteFindingDetail — minimal (no optional fields)
// ---------------------------------------------------------------------------

func TestWriteFindingDetail_Minimal(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:   "CTL.B.001",
			Name: "Test",
		},
		Asset: evaluation.FindingAssetSummary{
			ID:   "bucket-2",
			Type: "s3_bucket",
		},
		Evidence: evaluation.Evidence{},
	}

	var buf bytes.Buffer
	err := WriteFindingDetail(&buf, detail)
	if err != nil {
		t.Fatalf("WriteFindingDetail: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CTL.B.001") {
		t.Error("missing control ID")
	}
	// Should NOT contain optional sections
	if strings.Contains(out, "Remediation Guidance") {
		t.Error("unexpected remediation section")
	}
	if strings.Contains(out, "Next Steps") {
		t.Error("unexpected next steps section")
	}
}

// ---------------------------------------------------------------------------
// WriteFindingDetail — with trace (nil Raw)
// ---------------------------------------------------------------------------

func TestWriteFindingDetail_TraceNilRaw(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:   "CTL.C.001",
			Name: "Trace Test",
		},
		Asset: evaluation.FindingAssetSummary{
			ID:   "bucket-3",
			Type: "s3_bucket",
		},
		Evidence: evaluation.Evidence{},
		Trace:    &evaluation.FindingTrace{Raw: nil, FinalResult: false},
	}

	var buf bytes.Buffer
	err := WriteFindingDetail(&buf, detail)
	if err != nil {
		t.Fatalf("WriteFindingDetail: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "trace data unavailable") {
		t.Error("expected 'trace data unavailable' message")
	}
}

// ---------------------------------------------------------------------------
// titleCase
// ---------------------------------------------------------------------------

func TestTitleCase(t *testing.T) {
	if got := titleCase("high"); got != "High" {
		t.Fatalf("titleCase(high) = %q", got)
	}
	if got := titleCase(""); got != "" {
		t.Fatalf("titleCase('') = %q", got)
	}
	if got := titleCase("a"); got != "A" {
		t.Fatalf("titleCase(a) = %q", got)
	}
}

// ---------------------------------------------------------------------------
// writeField
// ---------------------------------------------------------------------------

func TestWriteField_EmptyLabel(t *testing.T) {
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeField(d, "", "some value")
	if !strings.Contains(buf.String(), "some value") {
		t.Fatal("should write value when label is empty")
	}
}

func TestWriteField_EmptyValue(t *testing.T) {
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeField(d, "Label", "")
	if buf.Len() != 0 {
		t.Fatal("should write nothing for empty value")
	}
}

func TestWriteField_WhitespaceOnlyValue(t *testing.T) {
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeField(d, "Label", "   ")
	if buf.Len() != 0 {
		t.Fatal("should write nothing for whitespace-only value")
	}
}

// ---------------------------------------------------------------------------
// writeOptionalStringField
// ---------------------------------------------------------------------------

func TestWriteOptionalStringField_Empty(t *testing.T) {
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeOptionalStringField(d, "  %s\n", "")
	if buf.Len() != 0 {
		t.Fatal("should write nothing for empty string")
	}
}

func TestWriteOptionalStringField_NonEmpty(t *testing.T) {
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeOptionalStringField(d, "  %s\n", "hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Fatal("should write value")
	}
}
