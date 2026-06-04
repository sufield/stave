package sirbridge

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestAWSS3FactGrouper_AllFourVectorsPopulated(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicRead",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::demo/*"
		}]
	}`
	bucket := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::demo"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"policy_json": policyJSON,
			"storage": map[string]any{
				"ownership_controls": "ObjectWriter",
				"controls": map[string]any{
					"public_access_block": map[string]any{
						"block_public_acls":       true,
						"ignore_public_acls":      false,
						"block_public_policy":     false,
						"restrict_public_buckets": false,
					},
				},
			},
			"get-bucket-acl": map[string]any{
				"Owner": map[string]any{"ID": "owner-1"},
				"Grants": []any{
					map[string]any{
						"Grantee":    map[string]any{"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
						"Permission": "READ",
					},
				},
			},
		},
	}
	role := asset.CloudIdentity{
		ID:     asset.ID("arn:aws:iam::111122223333:role/AppRole"),
		Type:   kernel.AssetType("aws_iam_role"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"identity": map[string]any{
				"policies_json": `{
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::demo/*"
					}]
				}`,
			},
		},
	}
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{bucket},
		Identities: []asset.CloudIdentity{role},
	}

	g := NewAWSS3FactGrouper()
	groups, err := g.GroupResources([]asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GroupResources: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	gr := groups[0]
	if gr.AssetID != "arn:aws:s3:::demo" {
		t.Errorf("AssetID: got %q", gr.AssetID)
	}
	if gr.Vendor != "aws" || gr.ServiceArea != "s3" {
		t.Errorf("Vendor/ServiceArea: got %q / %q", gr.Vendor, gr.ServiceArea)
	}
	if len(gr.BucketPolicy) != 1 {
		t.Errorf("BucketPolicy: want 1, got %d", len(gr.BucketPolicy))
	}
	if len(gr.ACLGrants) != 1 {
		t.Errorf("ACLGrants: want 1, got %d", len(gr.ACLGrants))
	}
	if !gr.ACLGrants[0].IsPublic {
		t.Errorf("ACL grant must have IsPublic=true: %+v", gr.ACLGrants[0])
	}
	if len(gr.PAB) != 1 {
		t.Errorf("PAB: want 1, got %d", len(gr.PAB))
	}
	if len(gr.AttachedIAM) != 1 {
		t.Errorf("AttachedIAM: want 1, got %d", len(gr.AttachedIAM))
	}
	if gr.AttachedIAM[0].AttachedTo == nil ||
		gr.AttachedIAM[0].AttachedTo.Value != "arn:aws:iam::111122223333:role/AppRole" {
		t.Errorf("AttachedIAM AttachedTo wrong: %+v", gr.AttachedIAM[0].AttachedTo)
	}
}

func TestAWSS3FactGrouper_NonS3AssetsSkipped(t *testing.T) {
	other := asset.Asset{
		ID:     asset.ID("arn:aws:dynamodb:::table/X"),
		Type:   kernel.AssetType("aws_dynamodb_table"),
		Vendor: kernel.Vendor("aws"),
	}
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{other},
	}
	g := NewAWSS3FactGrouper()
	groups, err := g.GroupResources([]asset.Snapshot{snap}, time.Time{})
	if err != nil {
		t.Fatalf("GroupResources: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("non-S3 assets must not produce groups; got %d", len(groups))
	}
}

func TestAWSS3FactGrouper_EmptyBucketProducesEmptyGroup(t *testing.T) {
	bucket := asset.Asset{
		ID:         asset.ID("arn:aws:s3:::empty"),
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     kernel.Vendor("aws"),
		Properties: map[string]any{},
	}
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{bucket},
	}
	g := NewAWSS3FactGrouper()
	groups, err := g.GroupResources([]asset.Snapshot{snap}, time.Time{})
	if err != nil {
		t.Fatalf("GroupResources: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group (empty), got %d", len(groups))
	}
	gr := groups[0]
	if len(gr.BucketPolicy) != 0 || len(gr.ACLGrants) != 0 || len(gr.PAB) != 0 || len(gr.AttachedIAM) != 0 {
		t.Errorf("all four vectors should be empty for bare bucket: %+v", gr)
	}
}

func TestAWSS3FactGrouper_MalformedACLFailsLoud(t *testing.T) {
	// A grant whose element is not an object is malformed. The grouper
	// must surface the parse error rather than collapse it to "no
	// grants" — a dropped malformed grant could hide a public grantee
	// and make the bucket look private.
	bucket := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::malformed-acl"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"get-bucket-acl": map[string]any{
				"Grants": []any{"not-an-object"},
			},
		},
	}
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{bucket},
	}
	g := NewAWSS3FactGrouper()
	if _, err := g.GroupResources([]asset.Snapshot{snap}, time.Time{}); err == nil {
		t.Fatal("malformed ACL must make GroupResources fail loud, got nil error")
	}
}

func TestAWSS3FactGrouper_MalformedBucketPolicyFailsLoud(t *testing.T) {
	// policy_json present but unparseable must surface as an error, not
	// silently erase a possibly-public statement.
	bucket := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::malformed-policy"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"policy_json": `{"Statement": [`,
		},
	}
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		Assets:     []asset.Asset{bucket},
	}
	g := NewAWSS3FactGrouper()
	if _, err := g.GroupResources([]asset.Snapshot{snap}, time.Time{}); err == nil {
		t.Fatal("malformed bucket policy must make GroupResources fail loud, got nil error")
	}
}
