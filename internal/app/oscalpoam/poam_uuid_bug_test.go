package oscalpoam

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestGenerate_DistinctAssetTypesProduceUniqueItemUUIDs(t *testing.T) {
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

	in := Input{
		Findings:   findings,
		SystemUUID: "sys-123",
		EvalTime:   time.Now(),
	}

	poam := Generate(in)
	if len(poam.Items) != 2 {
		t.Fatalf("expected 2 POAM items, got %d", len(poam.Items))
	}

	if poam.Items[0].UUID == poam.Items[1].UUID {
		t.Fatalf("duplicate POAM item UUID for different AssetTypes: %s", poam.Items[0].UUID)
	}
}
