package ocsf

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestExport_DistinctAssetTypesProduceUniqueUIDs(t *testing.T) {
	findings := []remediation.Finding{
		{
			ControlID: "CTL.S3.001",
			AssetID:   asset.ID("arn:aws:s3:::my-resource"),
			AssetType: "aws_s3_bucket",
		},
		{
			ControlID: "CTL.S3.001",
			AssetID:   asset.ID("arn:aws:s3:::my-resource"),
			AssetType: "aws_s3_access_point",
		},
	}

	events := Export(findings)
	if len(events) != 2 {
		t.Fatalf("expected 2 OCSF events, got %d", len(events))
	}

	if events[0].Finding.UID == events[1].Finding.UID {
		t.Fatalf("duplicate OCSF finding.uid for different AssetTypes: %s", events[0].Finding.UID)
	}
}
