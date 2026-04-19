package remediation

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestFormatRemediationAction_BucketNameSubstitution(t *testing.T) {
	a := asset.Asset{
		ID:   asset.ID("my-bucket"),
		Type: kernel.AssetType("aws_s3_bucket"),
	}
	out := FormatRemediationAction("aws s3api put-public-access-block --bucket <bucket-name>", a)
	if !strings.Contains(out, "--bucket my-bucket") {
		t.Errorf("expected <bucket-name> → my-bucket; got %q", out)
	}
	if strings.Contains(out, "<bucket-name>") {
		t.Errorf("placeholder should have been substituted; got %q", out)
	}
}

func TestFormatRemediationAction_RoleArnFromARN(t *testing.T) {
	a := asset.Asset{
		ID:   asset.ID("arn:aws:iam::111122223333:role/my-role"),
		Type: kernel.AssetType("aws_iam_role"),
	}
	out := FormatRemediationAction("attach --role-arn <role-arn> --role-name <role-name>", a)
	if !strings.Contains(out, "--role-arn arn:aws:iam::111122223333:role/my-role") {
		t.Errorf("<role-arn> not substituted correctly; got %q", out)
	}
	if !strings.Contains(out, "--role-name my-role") {
		t.Errorf("<role-name> should be ARN's short-id 'my-role'; got %q", out)
	}
}

func TestFormatRemediationAction_MultipleTokensInOneTemplate(t *testing.T) {
	a := asset.Asset{
		ID:   asset.ID("arn:aws:eks:us-west-2:111122223333:cluster/prod-eks"),
		Type: kernel.AssetType("aws_eks_cluster"),
	}
	tmpl := "aws eks update-cluster-config --name <cluster> --region <region> --account-id <account>"
	out := FormatRemediationAction(tmpl, a)
	if !strings.Contains(out, "--name prod-eks") {
		t.Errorf("<cluster> substitution failed: %q", out)
	}
	if !strings.Contains(out, "--region us-west-2") {
		t.Errorf("<region> substitution failed: %q", out)
	}
	if !strings.Contains(out, "--account-id 111122223333") {
		t.Errorf("<account> substitution failed: %q", out)
	}
}

func TestFormatRemediationAction_PlaceholderTypeMismatch(t *testing.T) {
	// <bucket-name> on an IAM role asset — placeholder leaves unchanged.
	a := asset.Asset{
		ID:   asset.ID("arn:aws:iam::111122223333:role/my-role"),
		Type: kernel.AssetType("aws_iam_role"),
	}
	out := FormatRemediationAction("fake command --bucket <bucket-name>", a)
	if !strings.Contains(out, "<bucket-name>") {
		t.Errorf("<bucket-name> on a role asset should be unchanged; got %q", out)
	}
}

func TestFormatRemediationAction_UnknownPlaceholderUnchanged(t *testing.T) {
	a := asset.Asset{
		ID:   asset.ID("my-bucket"),
		Type: kernel.AssetType("aws_s3_bucket"),
	}
	out := FormatRemediationAction("weird command --xyz <unknown-token>", a)
	if !strings.Contains(out, "<unknown-token>") {
		t.Errorf("unknown placeholder should pass through; got %q", out)
	}
}

func TestFormatRemediationAction_PreservesCurrentMarker(t *testing.T) {
	// <current> in multi-flag PAB commands must NEVER be substituted.
	a := asset.Asset{
		ID:   asset.ID("my-bucket"),
		Type: kernel.AssetType("aws_s3_bucket"),
	}
	tmpl := "aws s3api put-public-access-block --bucket <bucket-name> 'BlockPublicAcls=true,IgnorePublicAcls=<current>,BlockPublicPolicy=<current>,RestrictPublicBuckets=<current>'"
	out := FormatRemediationAction(tmpl, a)
	if !strings.Contains(out, "--bucket my-bucket") {
		t.Errorf("bucket name should substitute: %q", out)
	}
	if strings.Count(out, "<current>") != 3 {
		t.Errorf("<current> must be preserved, expected 3 occurrences; got %q", out)
	}
}

func TestFormatRemediationAction_NonARNAssetID(t *testing.T) {
	// Plain short names (not ARNs) still get <id>/<name> substitution
	// but no ARN-derived tokens.
	a := asset.Asset{
		ID:   asset.ID("test-ecs-service"),
		Type: kernel.AssetType("aws_ecs_service"),
	}
	out := FormatRemediationAction("aws ecs update-service --service <service> --region <region>", a)
	if !strings.Contains(out, "--service test-ecs-service") {
		t.Errorf("<service> should substitute: %q", out)
	}
	if !strings.Contains(out, "<region>") {
		t.Errorf("<region> has no source (non-ARN asset); should pass through: %q", out)
	}
}

func TestFormatRemediationAction_EmptyTemplate(t *testing.T) {
	a := asset.Asset{ID: asset.ID("x"), Type: kernel.AssetType("aws_s3_bucket")}
	if got := FormatRemediationAction("", a); got != "" {
		t.Errorf("empty template should stay empty; got %q", got)
	}
}
