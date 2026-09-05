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
	v, s, r := parseAssetID("arn:aws:s3:::prod-bucket")
	if v != "aws" || s != "s3" || r != "prod-bucket" {
		t.Errorf("parsed = %s/%s/%s, want aws/s3/prod-bucket", v, s, r)
	}
}
