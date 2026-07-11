package snapshot

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestExtractSummary_Basic(t *testing.T) {
	snapshots := asset.Snapshots{
		{
			Assets: []asset.Asset{
				{
					ID:     "res:aws:s3:bucket:test",
					Type:   kernel.AssetType("storage_bucket"),
					Vendor: "aws",
					Properties: map[string]any{
						"account_id": "123456789012",
						"region":     "us-east-1",
					},
				},
				{
					ID:     "res:aws:iam:role:admin",
					Type:   kernel.AssetType("iam_role"),
					Vendor: "aws",
					Properties: map[string]any{
						"account_id": "123456789012",
						"region":     "us-east-1",
					},
				},
				{
					ID:     "res:aws:cloudtrail:trail:main",
					Type:   kernel.AssetType("aws_cloudtrail_trail"),
					Vendor: "aws",
					Properties: map[string]any{
						"account_id": "123456789012",
						"region":     "us-east-1",
					},
				},
			},
		},
	}

	s := ExtractSummary(snapshots, true)

	if s.S3BucketCount != 1 {
		t.Fatalf("expected 1 S3 bucket, got %d", s.S3BucketCount)
	}
	if s.IAMRoleCount != 1 {
		t.Fatalf("expected 1 IAM role, got %d", s.IAMRoleCount)
	}
	if !s.HasCloudTrail {
		t.Fatal("expected HasCloudTrail=true")
	}
	if s.AccountCount != 1 {
		t.Fatalf("expected 1 account, got %d", s.AccountCount)
	}
	if s.RegionCount != 1 {
		t.Fatalf("expected 1 region, got %d", s.RegionCount)
	}
	if !s.EvalTimeSet {
		t.Fatal("expected EvalTimeSet=true")
	}
	if s.ResourceCount != 3 {
		t.Fatalf("expected 3 resources, got %d", s.ResourceCount)
	}
}
