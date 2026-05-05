package sirbridge

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func iamRole(arn, policiesJSON string) asset.CloudIdentity {
	return asset.CloudIdentity{
		ID:     asset.ID(arn),
		Type:   kernel.AssetType("aws_iam_role"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"identity": map[string]any{
				"policies_json": policiesJSON,
			},
		},
	}
}

func TestExtractIAMStatementsForAsset_BucketObjectGrant(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::mybucket/*"
		}]
	}`
	bucket := bucketAsset("arn:aws:s3:::mybucket", "")
	role := iamRole("arn:aws:iam::111122223333:role/AppRole", policyJSON)

	got := extractIAMStatementsForAsset(bucket, []asset.CloudIdentity{role})
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if got[0].Effect != "Allow" {
		t.Errorf("Effect: want Allow, got %q", got[0].Effect)
	}
	if got[0].AttachedTo == nil {
		t.Fatalf("AttachedTo nil")
	}
	if got[0].AttachedTo.Value != "arn:aws:iam::111122223333:role/AppRole" {
		t.Errorf("AttachedTo.Value: got %q", got[0].AttachedTo.Value)
	}
	if got[0].AttachedTo.Kind != "AWS_Role" {
		t.Errorf("AttachedTo.Kind: want AWS_Role, got %q", got[0].AttachedTo.Kind)
	}
	if got[0].Source.Kind != "iam_statement" {
		t.Errorf("Source.Kind: want iam_statement, got %q", got[0].Source.Kind)
	}
}

func TestExtractIAMStatementsForAsset_WildcardResource(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:*",
			"Resource": "*"
		}]
	}`
	bucket := bucketAsset("arn:aws:s3:::mybucket", "")
	role := iamRole("arn:aws:iam::111122223333:role/Admin", policyJSON)

	got := extractIAMStatementsForAsset(bucket, []asset.CloudIdentity{role})
	if len(got) != 1 {
		t.Fatalf("expected 1 statement (wildcard matches), got %d", len(got))
	}
	// Wildcard preserved literally — no expansion.
	if got[0].Resources[0] != "*" {
		t.Errorf("Resources[0]: want literal *, got %q", got[0].Resources[0])
	}
}

func TestExtractIAMStatementsForAsset_DifferentBucketSkipped(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::other-bucket/*"
		}]
	}`
	bucket := bucketAsset("arn:aws:s3:::mybucket", "")
	role := iamRole("arn:aws:iam::111122223333:role/AppRole", policyJSON)

	got := extractIAMStatementsForAsset(bucket, []asset.CloudIdentity{role})
	if len(got) != 0 {
		t.Errorf("statement targeting different bucket must not be included; got %d", len(got))
	}
}

func TestExtractIAMStatementsForAsset_BucketARNExactMatch(t *testing.T) {
	// Statement names the bucket ARN exactly (no /*) — should
	// match. Some bucket-scope IAM actions (e.g.
	// s3:ListBucket) target the bucket itself rather than
	// objects within it.
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:ListBucket",
			"Resource": "arn:aws:s3:::mybucket"
		}]
	}`
	bucket := bucketAsset("arn:aws:s3:::mybucket", "")
	role := iamRole("arn:aws:iam::111122223333:role/AppRole", policyJSON)

	got := extractIAMStatementsForAsset(bucket, []asset.CloudIdentity{role})
	if len(got) != 1 {
		t.Fatalf("exact-ARN match must be included; got %d", len(got))
	}
}

func TestExtractIAMStatementsForAsset_ConditionFlowThrough(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::mybucket/*",
			"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}
		}]
	}`
	bucket := bucketAsset("arn:aws:s3:::mybucket", "")
	role := iamRole("arn:aws:iam::111122223333:role/AppRole", policyJSON)

	got := extractIAMStatementsForAsset(bucket, []asset.CloudIdentity{role})
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if len(got[0].Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(got[0].Conditions))
	}
	cond := got[0].Conditions[0]
	if cond.Operator != "StringEquals" {
		t.Errorf("Operator: want StringEquals, got %q", cond.Operator)
	}
	if cond.Key != "aws:PrincipalOrgID" {
		t.Errorf("Key: want aws:PrincipalOrgID, got %q", cond.Key)
	}
	if len(cond.Values) != 1 || cond.Values[0] != "o-abc123" {
		t.Errorf("Values: want [o-abc123], got %v", cond.Values)
	}
}

func TestExtractIAMStatementsForAsset_NoIdentitiesReturnsNil(t *testing.T) {
	bucket := bucketAsset("arn:aws:s3:::mybucket", "")
	got := extractIAMStatementsForAsset(bucket, nil)
	if got != nil {
		t.Errorf("nil identities must return nil, got %+v", got)
	}
}
