package iam

import (
	"slices"
	"testing"
)

func TestDefaultRegistryLen(t *testing.T) {
	r := DefaultRegistry()
	if r.Len() < 400 {
		t.Fatalf("expected ≥400 actions, got %d", r.Len())
	}
}

func TestClassifyKnownActions(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		action string
		want   ActionRiskCategory
	}{
		{"iam:CreateAccessKey", ActionCredentialExposure},
		{"iam:CreateAccessKey", ActionPrivEsc},
		{"s3:GetObject", ActionDataAccess},
		{"iam:PassRole", ActionPrivEsc},
		{"s3:PutBucketPolicy", ActionResourceExposure},
		{"sts:AssumeRole", ActionCredentialExposure},
		{"cloudtrail:StopLogging", ActionResourceExposure},
		{"bedrock:InvokeModel", ActionDataAccess},
	}
	for _, tt := range tests {
		cats := r.Classify(tt.action)
		if !slices.Contains(cats, tt.want) {
			t.Errorf("Classify(%q) = %v, want %v included", tt.action, cats, tt.want)
		}
	}
}

func TestClassifyCaseInsensitive(t *testing.T) {
	r := DefaultRegistry()
	cats := r.Classify("IAM:CREATEACCESSKEY")
	if !slices.Contains(cats, ActionCredentialExposure) {
		t.Errorf("case-insensitive lookup failed: got %v", cats)
	}
}

func TestClassifyUnknownAction(t *testing.T) {
	r := DefaultRegistry()
	if cats := r.Classify("nosuchservice:NoSuchAction"); cats != nil {
		t.Errorf("expected nil for unknown action, got %v", cats)
	}
}

func TestClassifyWildcardServiceStar(t *testing.T) {
	r := DefaultRegistry()
	cats := r.ClassifyWildcard("iam:*")
	if len(cats) == 0 {
		t.Fatal("iam:* should match IAM actions")
	}
	if !slices.Contains(cats, ActionCredentialExposure) {
		t.Error("iam:* missing CredentialExposure")
	}
	if !slices.Contains(cats, ActionPrivEsc) {
		t.Error("iam:* missing PrivEsc")
	}
	if !slices.Contains(cats, ActionResourceExposure) {
		t.Error("iam:* missing ResourceExposure")
	}
}

func TestClassifyWildcardPrefix(t *testing.T) {
	r := DefaultRegistry()
	cats := r.ClassifyWildcard("s3:Put*")
	if !slices.Contains(cats, ActionResourceExposure) {
		t.Errorf("s3:Put* should include ResourceExposure, got %v", cats)
	}
}

func TestClassifyWildcardStar(t *testing.T) {
	r := DefaultRegistry()
	cats := r.ClassifyWildcard("*")
	if len(cats) != 5 {
		t.Errorf("* should return all 5 categories, got %d", len(cats))
	}
}

func TestHasDataAccess(t *testing.T) {
	r := DefaultRegistry()
	if !r.HasDataAccess("s3:GetObject") {
		t.Error("s3:GetObject should have DataAccess")
	}
	if !r.HasDataAccess("s3:Get*") {
		t.Error("s3:Get* should have DataAccess")
	}
	if r.HasDataAccess("iam:PassRole") {
		t.Error("iam:PassRole should not have DataAccess")
	}
}

func TestHasCredentialExposure(t *testing.T) {
	r := DefaultRegistry()
	if !r.HasCredentialExposure("sts:AssumeRole") {
		t.Error("sts:AssumeRole should have CredentialExposure")
	}
	if r.HasCredentialExposure("s3:PutObject") {
		t.Error("s3:PutObject should not have CredentialExposure")
	}
}

func TestCountByCategory(t *testing.T) {
	r := DefaultRegistry()
	actions := []string{
		"s3:GetObject",
		"s3:PutBucketPolicy",
		"iam:CreateAccessKey",
		"nosuchservice:Nope",
	}
	n := r.CountByCategory(actions, ActionDataAccess)
	if n != 1 {
		t.Errorf("expected 1 DataAccess action, got %d", n)
	}
}

func TestMultiCategoryAction(t *testing.T) {
	r := DefaultRegistry()
	cats := r.Classify("iam:CreateAccessKey")
	if len(cats) < 2 {
		t.Fatalf("iam:CreateAccessKey should be in ≥2 categories, got %d", len(cats))
	}
}

func TestStaveGapAdditions(t *testing.T) {
	r := DefaultRegistry()

	staveActions := []string{
		"bedrock:InvokeModel",
		"sts:AssumeRoot",
		"organizations:LeaveOrganization",
		"verifiedpermissions:CreatePolicy",
		"s3express:GetObject",
		"s3tables:GetTableObject",
		"s3vectors:SearchVectors",
		"s3tables:PutTableBucketPolicy",
		"s3vectors:DeleteVectorBucketPolicy",
	}
	for _, a := range staveActions {
		if cats := r.Classify(a); cats == nil {
			t.Errorf("stave gap action %q not in registry", a)
		}
	}
}

func TestRedshiftServerlessMultiCategory(t *testing.T) {
	r := DefaultRegistry()
	cats := r.Classify("redshift-serverless:GetCredentials")
	if !slices.Contains(cats, ActionCredentialExposure) {
		t.Error("redshift-serverless:GetCredentials should have CredentialExposure")
	}
	if !slices.Contains(cats, ActionDataAccess) {
		t.Error("redshift-serverless:GetCredentials should have DataAccess")
	}
}

func TestSARPMGapAdditions(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		action string
		want   []ActionRiskCategory
	}{
		{"codebuild:PutResourcePolicy", []ActionRiskCategory{ActionResourceExposure}},
		{"dynamodb:DeleteResourcePolicy", []ActionRiskCategory{ActionResourceExposure}},
		{"iam:DeleteGroupPolicy", []ActionRiskCategory{ActionPrivEsc}},
		{"iam:DetachGroupPolicy", []ActionRiskCategory{ActionPrivEsc}},
		{"sso:AttachManagedPolicyToPermissionSet", []ActionRiskCategory{ActionPrivEsc}},
		{"sso:UpdatePermissionSet", []ActionRiskCategory{ActionPrivEsc}},
		{"lambda:RemovePermission", []ActionRiskCategory{ActionResourceExposure}},
		{"kms:RevokeGrant", []ActionRiskCategory{ActionResourceExposure}},
		{"s3:PutBucketPublicAccessBlock", []ActionRiskCategory{ActionResourceExposure}},
		{"s3:BypassGovernanceRetention", []ActionRiskCategory{ActionResourceExposure, ActionPrivEsc}},
		{"ec2:ModifyVpcEndpointServicePermissions", []ActionRiskCategory{ActionResourceExposure}},
		{"redshift:ModifyClusterIamRoles", []ActionRiskCategory{ActionPrivEsc}},
		{"redshift:AuthorizeDataShare", []ActionRiskCategory{ActionResourceExposure}},
	}
	for _, tt := range tests {
		cats := r.Classify(tt.action)
		if cats == nil {
			t.Errorf("Classify(%q) = nil, want %v", tt.action, tt.want)
			continue
		}
		for _, w := range tt.want {
			if !slices.Contains(cats, w) {
				t.Errorf("Classify(%q) = %v, missing %v", tt.action, cats, w)
			}
		}
	}
}

func TestSARPMGapCount(t *testing.T) {
	count := 0
	for _, a := range defaultActions {
		if a.Source == "sar-pm-2026-07" {
			count++
		}
	}
	if count != 48 {
		t.Errorf("expected 48 sar-pm-2026-07 actions, got %d", count)
	}
}

func TestCategoryMergingForMultiListActions(t *testing.T) {
	r := DefaultRegistry()
	// iam:CreateAccessKey appears in CredentialExposure AND PrivEsc in Farris seed
	cats := r.Classify("iam:CreateAccessKey")
	if !slices.Contains(cats, ActionCredentialExposure) {
		t.Error("iam:CreateAccessKey should have CredentialExposure after merge")
	}
	if !slices.Contains(cats, ActionPrivEsc) {
		t.Error("iam:CreateAccessKey should have PrivEsc after merge")
	}
}
