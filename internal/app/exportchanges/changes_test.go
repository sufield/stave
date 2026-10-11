package exportchanges

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestExport_ConfidenceFilter(t *testing.T) {
	findings := []remediation.Finding{
		{
			ControlID:       kernel.ControlID("CTL.S3.PUBLIC.001"),
			AssetID:         asset.ID("arn:aws:s3:::prod-bucket"),
			AssetType:       "s3_bucket",
			ControlSeverity: policy.SeverityCritical,
			RemediationSpec: policy.RemediationSpec{
				Confidence: 1.0,
				Changes: []policy.PropertyChange{
					{PropertyPath: "public_access_block", CurrentValue: "false", RequiredValue: "true", HasSafeDefault: true},
				},
			},
		},
		{
			ControlID:       kernel.ControlID("CTL.S3.ENCRYPT.001"),
			AssetID:         asset.ID("arn:aws:s3:::log-bucket"),
			AssetType:       "s3_bucket",
			ControlSeverity: policy.SeverityHigh,
			RemediationSpec: policy.RemediationSpec{
				Confidence: 0.5,
				Changes: []policy.PropertyChange{
					{PropertyPath: "encryption", CurrentValue: "none", RequiredValue: "aes256"},
				},
			},
		},
	}

	result := Export(Input{
		Findings:      findings,
		MinConfidence: 0.9,
		GeneratedAt:   "2026-04-15T00:00:00Z",
	})

	if len(result.Changes) != 1 {
		t.Fatalf("changes = %d, want 1 (filtered by confidence)", len(result.Changes))
	}
	if result.Changes[0].ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("control = %s, want CTL.S3.PUBLIC.001", result.Changes[0].ControlID)
	}
}

func TestExport_ParseARN(t *testing.T) {
	v, s, r := parseAssetID(asset.ID("arn:aws:s3:::prod-bucket"))
	if v != "aws" || s != "s3" || r != "prod-bucket" {
		t.Errorf("parsed = %s/%s/%s, want aws/s3/prod-bucket", v, s, r)
	}
}

func TestChanges_CollectionMethods(t *testing.T) {
	cs := Changes{
		{ControlID: "CTL-1", Severity: policy.SeverityCritical, Confidence: 1.0},
		{ControlID: "CTL-2", Severity: policy.SeverityHigh, Confidence: 0.5},
		{ControlID: "CTL-1", Severity: policy.SeverityHigh, Confidence: 0.8},
	}

	if cs.Len() != 3 {
		t.Errorf("cs.Len() = %d, want 3", cs.Len())
	}

	if cs.FilterByMinConfidence(0.8).Len() != 2 {
		t.Errorf("FilterByMinConfidence(0.8) len = %d, want 2", cs.FilterByMinConfidence(0.8).Len())
	}

	if cs.BySeverity(policy.SeverityCritical).Len() != 1 {
		t.Errorf("BySeverity(Critical) len = %d, want 1", cs.BySeverity(policy.SeverityCritical).Len())
	}

	if cs.ByControl("CTL-1").Len() != 2 {
		t.Errorf("ByControl(CTL-1) len = %d, want 2", cs.ByControl("CTL-1").Len())
	}
}

func TestFindingList_DomainMethods(t *testing.T) {
	fl := FindingList{
		{ControlID: "CTL.S3.PUBLIC.001"},
		{ControlID: "CTL.S3.ENCRYPT.001"},
		{ControlID: "CTL.S3.PUBLIC.001"},
	}

	if fl.Len() != 3 {
		t.Errorf("fl.Len() = %d, want 3", fl.Len())
	}

	if fl.ByControl("CTL.S3.PUBLIC.001").Len() != 2 {
		t.Errorf("ByControl(CTL.S3.PUBLIC.001) len = %d, want 2", fl.ByControl("CTL.S3.PUBLIC.001").Len())
	}
	if fl.ByControl("CTL.S3.ABSENT.001").Len() != 0 {
		t.Errorf("ByControl(CTL.S3.ABSENT.001) len = %d, want 0", fl.ByControl("CTL.S3.ABSENT.001").Len())
	}
}

func TestConfidenceScore_DomainMethods(t *testing.T) {
	c := ConfidenceScore(0.85)
	if c.Float64() != 0.85 {
		t.Errorf("Float64() = %v, want 0.85", c.Float64())
	}
	if c.Percentage() != 85.0 {
		t.Errorf("Percentage() = %v, want 85.0", c.Percentage())
	}
	if !c.IsHigh() {
		t.Error("IsHigh() = false for 0.85, want true")
	}
	if c.IsLow() {
		t.Error("IsLow() = true for 0.85, want false")
	}
	if !c.IsSufficient(0.8) {
		t.Error("IsSufficient(0.8) = false for 0.85, want true")
	}
	if c.IsSufficient(0.9) {
		t.Error("IsSufficient(0.9) = true for 0.85, want false")
	}
	if c.IsZero() {
		t.Error("IsZero() = true for 0.85, want false")
	}

	low := ConfidenceScore(0.3)
	if low.IsHigh() {
		t.Error("IsHigh() = true for 0.3, want false")
	}
	if !low.IsLow() {
		t.Error("IsLow() = false for 0.3, want true")
	}

	zero := ConfidenceScore(0)
	if !zero.IsZero() {
		t.Error("IsZero() = false for 0, want true")
	}
}

