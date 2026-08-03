package oscal

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestExport_DistinctAssetTypesProduceUniqueUUIDs(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.001",
				AssetID:   asset.ID("arn:aws:s3:::my-resource"),
				AssetType: "aws_s3_bucket",
			},
		},
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.001",
				AssetID:   asset.ID("arn:aws:s3:::my-resource"),
				AssetType: "aws_s3_access_point",
			},
		},
	}

	res := Export(findings, time.Now())
	if len(res.AR.Results) == 0 {
		t.Fatalf("expected results")
	}

	arFindings := res.AR.Results[0].Findings
	if len(arFindings) != 2 {
		t.Fatalf("expected 2 OSCAL findings, got %d", len(arFindings))
	}

	if arFindings[0].UUID == arFindings[1].UUID {
		t.Fatalf("duplicate OSCAL finding UUID for different AssetTypes: %s", arFindings[0].UUID)
	}
}
