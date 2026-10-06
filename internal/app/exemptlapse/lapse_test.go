package exemptlapse

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

var now = time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

func TestDetect_ExpiredExemptionProducesLapsed(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"),
			AssetID:   asset.ID("arn:aws:s3:::prod-bucket"),
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:             "acknowledgment",
				ExpiryDate:       "2026-01-01",
				AcknowledgedDate: "2025-10-01",
				Valid:            false,
				InvalidReason:    "expired",
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}
	if result[0].FindingType != "EXEMPTION_LAPSED" {
		t.Errorf("type = %s, want EXEMPTION_LAPSED", result[0].FindingType)
	}
	if result[0].DaysSinceExpiry < 100 {
		t.Errorf("days = %d, want >= 100", result[0].DaysSinceExpiry)
	}
}

func TestDetect_SeverityBumpAfter30Days(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			AssetID:   "asset1",
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:          "acknowledgment",
				ExpiryDate:    "2026-03-01",
				Valid:         false,
				InvalidReason: "expired",
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}
	if result[0].Severity == result[0].OriginalSeverity {
		t.Error("severity should be bumped after 30+ days past expiry")
	}
	if result[0].SeverityBumpReason == "" {
		t.Error("bump reason should be set")
	}
}

func TestDetect_CompensatingControlFailureSurfaces(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			AssetID:   "asset1",
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:          "acknowledgment",
				ExpiryDate:    "2026-05-01",
				Valid:         false,
				InvalidReason: "compensating_controls_failing",
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}
	if result[0].CompensatingNote == "" {
		t.Error("compensating note should be set")
	}
}

func TestDetect_ActiveExemptionStillSuppresses(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			AssetID:   "asset1",
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:       "acknowledgment",
				ExpiryDate: "2026-12-31",
				Valid:      true,
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 0 {
		t.Errorf("lapsed = %d, want 0 (active exemption)", len(result))
	}
}

func TestLapsedFindings_DomainMethods(t *testing.T) {
	lf := LapsedFindings{
		{ControlID: "CTL.A", Severity: policy.SeverityHigh, SeverityBumpReason: "expired"},
		{ControlID: "CTL.B", Severity: policy.SeverityMedium},
		{ControlID: "CTL.C", Severity: policy.SeverityHigh, SeverityBumpReason: "expired"},
	}

	if lf.Len() != 3 {
		t.Errorf("Len: got %d, want 3", lf.Len())
	}
	if lf.BumpedCount() != 2 {
		t.Errorf("BumpedCount: got %d, want 2", lf.BumpedCount())
	}
	if highs := lf.BySeverity(policy.SeverityHigh); highs.Len() != 2 {
		t.Errorf("BySeverity High: got %d, want 2", highs.Len())
	}
}

func TestDaysSinceExpiry_DomainMethods(t *testing.T) {
	d := DaysSinceExpiry(45)

	if d.Int() != 45 {
		t.Errorf("Int() = %d, want 45", d.Int())
	}
	if !d.IsSeverityBumped() {
		t.Error("IsSeverityBumped() = false, want true for 45 days")
	}
	if DaysSinceExpiry(15).IsSeverityBumped() {
		t.Error("IsSeverityBumped() = true, want false for 15 days")
	}
	if d.Duration() != 45*24*time.Hour {
		t.Errorf("Duration() = %v, want %v", d.Duration(), 45*24*time.Hour)
	}
}

func TestExemptionID_DomainMethods(t *testing.T) {
	id := NewExemptionID("CTL.S3.PUBLIC.001", "aws_s3_bucket", "arn:aws:s3:::my-bucket")
	if id.String() != "CTL.S3.PUBLIC.001@aws_s3_bucket@arn:aws:s3:::my-bucket" {
		t.Errorf("String() = %q", id.String())
	}
	if id.IsEmpty() {
		t.Error("IsEmpty() returned true for non-empty ID")
	}
	if id.ControlID() != "CTL.S3.PUBLIC.001" {
		t.Errorf("ControlID() = %q, want %q", id.ControlID(), "CTL.S3.PUBLIC.001")
	}
	if id.AssetID() != "arn:aws:s3:::my-bucket" {
		t.Errorf("AssetID() = %q, want %q", id.AssetID(), "arn:aws:s3:::my-bucket")
	}

	simpleID := NewExemptionID("CTL.EC2.001", "", "arn:aws:ec2:::instance-1")
	if simpleID.String() != "CTL.EC2.001@arn:aws:ec2:::instance-1" {
		t.Errorf("String() = %q", simpleID.String())
	}
	if simpleID.ControlID() != "CTL.EC2.001" {
		t.Errorf("ControlID() = %q, want %q", simpleID.ControlID(), "CTL.EC2.001")
	}
	if simpleID.AssetID() != "arn:aws:ec2:::instance-1" {
		t.Errorf("AssetID() = %q, want %q", simpleID.AssetID(), "arn:aws:ec2:::instance-1")
	}

	emptyID := ExemptionID("   ")
	if !emptyID.IsEmpty() {
		t.Error("IsEmpty() returned false for whitespace ID")
	}
}
