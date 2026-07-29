package reporting

import (
	"testing"
)

func TestCompareFindings_DistinctAssetTypePreserved(t *testing.T) {
	baseline := []BaselineFinding{}
	current := []BaselineFinding{
		{
			ControlID:   "CTL.S3.001",
			ControlName: "S3 Control",
			AssetID:     "arn:aws:s3:::my-bucket",
			AssetType:   "aws_s3_bucket",
		},
		{
			ControlID:   "CTL.S3.001",
			ControlName: "S3 Control",
			AssetID:     "arn:aws:s3:::my-bucket",
			AssetType:   "aws_s3_access_point",
		},
	}

	newFindings, _, _ := compareFindings(baseline, current)
	if len(newFindings) != 2 {
		t.Fatalf("expected 2 new findings for different AssetTypes on same AssetID, got %d", len(newFindings))
	}
}
