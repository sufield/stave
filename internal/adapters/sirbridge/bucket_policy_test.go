package sirbridge

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
)

func bucketAsset(id, policyJSON string) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"policy_json": policyJSON,
		},
	}
}

func TestExtractBucketPolicyStatements_PublicReadSingleStatement(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicRead",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`
	got, err := extractBucketPolicyStatements(bucketAsset("arn:aws:s3:::my-bucket", policyJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	stmt := got[0]
	if stmt.StatementIndex != 0 {
		t.Errorf("StatementIndex: want 0, got %d", stmt.StatementIndex)
	}
	if stmt.Sid != "PublicRead" {
		t.Errorf("Sid: want PublicRead, got %q", stmt.Sid)
	}
	if stmt.Effect != "Allow" {
		t.Errorf("Effect: want Allow, got %q", stmt.Effect)
	}
	if len(stmt.Principals) != 1 {
		t.Fatalf("Principals: want 1, got %d", len(stmt.Principals))
	}
	if !stmt.Principals[0].IsPublic {
		t.Errorf("wildcard principal must have IsPublic=true: %+v", stmt.Principals[0])
	}
	if stmt.Principals[0].Kind != "Wildcard" {
		t.Errorf("wildcard kind: want Wildcard, got %q", stmt.Principals[0].Kind)
	}
	if !reflect.DeepEqual(stmt.Source.Path, []string{"Statement", "0"}) {
		t.Errorf("Source.Path: want [Statement 0], got %v", stmt.Source.Path)
	}
}

func TestExtractBucketPolicyStatements_AllowAndDenyTwoStatements(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::111122223333:role/AppRole"},
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*"
			},
			{
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:DeleteObject",
				"Resource": "arn:aws:s3:::my-bucket/*"
			}
		]
	}`
	got, err := extractBucketPolicyStatements(bucketAsset("arn:aws:s3:::my-bucket", policyJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(got))
	}
	if got[0].StatementIndex != 0 || got[1].StatementIndex != 1 {
		t.Errorf("indices not 0,1: got %d,%d", got[0].StatementIndex, got[1].StatementIndex)
	}
	if got[0].Effect != "Allow" {
		t.Errorf("stmt[0].Effect: want Allow, got %q", got[0].Effect)
	}
	if got[1].Effect != "Deny" {
		t.Errorf("stmt[1].Effect: want Deny, got %q", got[1].Effect)
	}
	if got[0].Principals[0].IsPublic {
		t.Errorf("stmt[0] AWS-ARN principal must NOT be IsPublic: %+v", got[0].Principals[0])
	}
	if got[0].Principals[0].Kind != "AWS" {
		t.Errorf("stmt[0] kind: want AWS, got %q", got[0].Principals[0].Kind)
	}
	if !got[1].Principals[0].IsPublic {
		t.Errorf("stmt[1] wildcard principal must be IsPublic: %+v", got[1].Principals[0])
	}
}

func TestExtractBucketPolicyStatements_ConditionWithIPAddress(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]}
			}
		}]
	}`
	got, err := extractBucketPolicyStatements(bucketAsset("arn:aws:s3:::my-bucket", policyJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if len(got[0].Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(got[0].Conditions))
	}
	cond := got[0].Conditions[0]
	if cond.Operator != "IpAddress" {
		t.Errorf("Operator: want IpAddress, got %q", cond.Operator)
	}
	if cond.Key != "aws:SourceIp" {
		t.Errorf("Key: want aws:SourceIp, got %q", cond.Key)
	}
	wantValues := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if !reflect.DeepEqual(cond.Values, wantValues) {
		t.Errorf("Values: want %v, got %v", wantValues, cond.Values)
	}
	wantPath := []string{"Statement", "0", "Condition", "IpAddress", "aws:SourceIp"}
	if !reflect.DeepEqual(cond.Source.Path, wantPath) {
		t.Errorf("Condition Source.Path: want %v, got %v", wantPath, cond.Source.Path)
	}
}

func TestExtractBucketPolicyStatements_NoPolicyReturnsNil(t *testing.T) {
	a := asset.Asset{
		ID:         asset.ID("arn:aws:s3:::no-policy"),
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     kernel.Vendor("aws"),
		Properties: map[string]any{},
	}
	got, err := extractBucketPolicyStatements(a)
	if err != nil {
		t.Fatalf("absent policy must not error, got %v", err)
	}
	if got != nil {
		t.Errorf("absent policy must return nil, got %+v", got)
	}
}

func TestExtractBucketPolicyStatements_MalformedJSONErrors(t *testing.T) {
	// policy_json present but not valid JSON: must fail loud, not
	// silently return zero statements (which would erase a possibly
	// public statement and make the bucket look private).
	got, err := extractBucketPolicyStatements(bucketAsset("arn:aws:s3:::my-bucket", `{"Statement": [`))
	if err == nil {
		t.Fatalf("malformed policy_json must return an error, got nil (facts=%+v)", got)
	}
	if got != nil {
		t.Errorf("malformed policy_json must return nil facts alongside the error, got %+v", got)
	}
}

func TestExtractBucketPolicyStatements_ServicePrincipal(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "logging.s3.amazonaws.com"},
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`
	got, err := extractBucketPolicyStatements(bucketAsset("arn:aws:s3:::my-bucket", policyJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	stmt := got[0]
	if len(stmt.Principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(stmt.Principals))
	}
	if stmt.Principals[0].Kind != "Service" {
		t.Errorf("Kind: want Service, got %q", stmt.Principals[0].Kind)
	}
	if stmt.Principals[0].Value != "logging.s3.amazonaws.com" {
		t.Errorf("Value: want logging.s3.amazonaws.com, got %q", stmt.Principals[0].Value)
	}
	if stmt.Principals[0].IsPublic {
		t.Errorf("Service principal must NOT be IsPublic: %+v", stmt.Principals[0])
	}
}

// Various sir/sirbridge assertions reference these paths. Pin the
// SourceRef Kind constants so test failures point at the
// schema-mismatch site rather than at field-equality diffs.
var _ = sir.SourceRef{Kind: "statement"}
