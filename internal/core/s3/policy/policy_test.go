package policy

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func mustAssess(t *testing.T, policyJSON string) Assessment {
	t.Helper()
	doc, err := Parse(policyJSON)
	if err != nil {
		return Assessment{}
	}
	return doc.Assess()
}

func TestAnalyzePolicyPublicReadWrite(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicAccess",
			"Effect": "Allow",
			"Principal": "*",
			"Action": ["s3:GetObject", "s3:ListBucket"],
			"Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=true")
	}
	if !result.AllowsPublicList {
		t.Error("expected AllowsPublicList=true")
	}
	if len(result.PublicStatements) != 1 || result.PublicStatements[0] != "sid:PublicAccess" {
		t.Errorf("expected PublicStatements=[sid:PublicAccess], got %v", result.PublicStatements)
	}
}

func TestAnalyzePolicyAWSPrincipal(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "*"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=true for Principal.AWS=*")
	}
}

func TestAnalyzePolicyAWSPrincipalArray(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": ["*"]},
			"Action": "s3:*",
			"Resource": "*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=true for Principal.AWS=[*]")
	}
	if !result.AllowsPublicList {
		t.Error("expected AllowsPublicList=true for s3:*")
	}
}

func TestAnalyzePolicyDeny(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false for Deny effect")
	}
	if result.AllowsPublicList {
		t.Error("expected AllowsPublicList=false for Deny effect")
	}
}

func TestAnalyzePolicyPrivate(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "s3:*",
			"Resource": "*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false for specific account")
	}
	if result.AllowsPublicList {
		t.Error("expected AllowsPublicList=false for specific account")
	}
}

func TestAnalyzePolicyEmpty(t *testing.T) {
	result := mustAssess(t, "")

	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false for empty policy")
	}
	if result.AllowsPublicList {
		t.Error("expected AllowsPublicList=false for empty policy")
	}
}

func TestAnalyzePolicyInvalidJSON(t *testing.T) {
	result := mustAssess(t, "not valid json")

	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false for invalid JSON")
	}
}

func TestAnalyzePolicyPublicWrite(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicWrite",
			"Effect": "Allow",
			"Principal": "*",
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicWrite {
		t.Error("expected AllowsPublicWrite=true")
	}
	if result.AllowsPublicDelete {
		t.Error("expected AllowsPublicDelete=false for PutObject-only")
	}
}

func TestAnalyzePolicyPublicDelete(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicDelete",
			"Effect": "Allow",
			"Principal": "*",
			"Action": ["s3:DeleteObject", "s3:DeleteBucket"],
			"Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicDelete {
		t.Error("expected AllowsPublicDelete=true")
	}
	if result.AllowsPublicWrite {
		t.Error("expected AllowsPublicWrite=false for Delete-only")
	}
}

func TestAnalyzePolicyS3WildcardSetsWriteAndDelete(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicWrite {
		t.Error("expected AllowsPublicWrite=true for s3:*")
	}
	if !result.AllowsPublicDelete {
		t.Error("expected AllowsPublicDelete=true for s3:*")
	}
	if !result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=true for s3:*")
	}
	if !result.HasWildcardActions {
		t.Error("expected HasWildcardActions=true for s3:* with Resource=*")
	}
}

func TestAnalyzePolicyWildcardActions(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "*",
			"Resource": "arn:aws:s3:::*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.HasWildcardActions {
		t.Error("expected HasWildcardActions=true for Action=* with Resource=arn:aws:s3:::*")
	}
}

func TestAnalyzePolicyWildcardActionSpecificResource(t *testing.T) {
	// Wildcard action but specific resource — not a wildcard policy
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-specific-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.HasWildcardActions {
		t.Error("expected HasWildcardActions=false when resource is specific")
	}
}

func TestAnalyzePolicyPutBucketPolicy(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:PutBucketPolicy",
			"Resource": "arn:aws:s3:::my-bucket"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicWrite {
		t.Error("expected AllowsPublicWrite=true for PutBucketPolicy")
	}
}

// Transport encryption tests

func TestAnalyzeTransportEncryptionEnforced(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"Bool": {
					"aws:SecureTransport": "false"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if !result.EnforcesHTTPS {
		t.Error("expected EnforcesHTTPS=true for Deny with SecureTransport condition")
	}
}

func TestAnalyzeTransportEncryptionMissingCondition(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.EnforcesHTTPS {
		t.Error("expected EnforcesHTTPS=false when condition is missing")
	}
}

func TestAnalyzeTransportEncryptionAllowNotDeny(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"Bool": {
					"aws:SecureTransport": "false"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.EnforcesHTTPS {
		t.Error("expected EnforcesHTTPS=false for Allow effect (must be Deny)")
	}
}

func TestAnalyzeTransportEncryptionBooleanFalseCondition(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"Bool": {
					"aws:SecureTransport": false
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if !result.EnforcesHTTPS {
		t.Error("expected EnforcesHTTPS=true for boolean false SecureTransport condition")
	}
}

func TestAnalyzeTransportEncryptionMalformedSecureTransportValue(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"Bool": {
					"aws:SecureTransport": 0
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.EnforcesHTTPS {
		t.Error("expected EnforcesHTTPS=false for malformed SecureTransport condition value")
	}
}

func TestAnalyzePolicyCondition_SourceVPCE_StringLike_IsRestrictive(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringLike": {
					"aws:sourceVpce": "vpce-*"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false when restricted by source VPCE condition")
	}
	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true for source VPCE condition")
	}
	if result.EffectiveNetworkScope != kernel.NetworkScopeVPCRestricted {
		t.Errorf("expected EffectiveNetworkScope=vpc-restricted, got %q", result.EffectiveNetworkScope)
	}
}

func TestAnalyzePolicyCondition_SourceVPC_ArnEquals_IsRestrictive(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "*"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"ArnEquals": {
					"AWS:SourceVpc": "vpc-1234567890abcdef0"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false when restricted by source VPC condition")
	}
	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true for source VPC condition")
	}
}

func TestAnalyzePolicyCondition_PrincipalOrgID_StringEquals_IsRestrictive(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:ListBucket",
			"Resource": "arn:aws:s3:::my-bucket",
			"Condition": {
				"StringEquals": {
					"aws:PrincipalOrgID": "o-1234567890"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicList {
		t.Error("expected AllowsPublicList=false when restricted by principal org condition")
	}
	if result.EffectiveNetworkScope != kernel.NetworkScopeOrgRestricted {
		t.Errorf("expected EffectiveNetworkScope=org-restricted, got %q", result.EffectiveNetworkScope)
	}
}

func TestAnalyzeTransportEncryptionEmpty(t *testing.T) {
	result := mustAssess(t, "")

	if result.EnforcesHTTPS {
		t.Error("expected EnforcesHTTPS=false for empty policy")
	}
}

// Cross-account access tests

func TestCrossAccountAccess(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.HasExternalAccess {
		t.Error("expected HasExternalAccess=true")
	}
	if len(result.ExternalAccountARNs) != 1 {
		t.Fatalf("expected 1 external ARN, got %d", len(result.ExternalAccountARNs))
	}
	if result.ExternalAccountARNs[0] != AWSAccountARN("arn:aws:iam::999888777666:root") {
		t.Errorf("expected ARN 'arn:aws:iam::999888777666:root', got %q", result.ExternalAccountARNs[0])
	}
	if len(result.ExternalAccountIDs) != 1 {
		t.Fatalf("expected 1 external account ID, got %d", len(result.ExternalAccountIDs))
	}
	if result.ExternalAccountIDs[0] != AWSAccountID("999888777666") {
		t.Errorf("expected account ID '999888777666', got %q", result.ExternalAccountIDs[0])
	}
}

func TestAnalyzeCrossAccountAccessMultiple(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": ["arn:aws:iam::111222333444:root", "arn:aws:iam::555666777888:role/reader"]},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.HasExternalAccess {
		t.Error("expected HasExternalAccess=true")
	}
	if len(result.ExternalAccountARNs) != 2 {
		t.Fatalf("expected 2 external ARNs, got %d", len(result.ExternalAccountARNs))
	}
	if len(result.ExternalAccountIDs) != 2 {
		t.Fatalf("expected 2 external account IDs, got %d", len(result.ExternalAccountIDs))
	}
}

func TestAnalyzeCrossAccountAccessPublicPrincipal(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.HasExternalAccess {
		t.Error("expected HasExternalAccess=false for public principal (handled by public access check)")
	}
}

func TestAnalyzeCrossAccountAccessDenyIgnored(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": "s3:*",
			"Resource": "*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.HasExternalAccess {
		t.Error("expected HasExternalAccess=false for Deny statements")
	}
}

func TestAnalyzeCrossAccountAccessEmpty(t *testing.T) {
	result := mustAssess(t, "")

	if result.HasExternalAccess {
		t.Error("expected HasExternalAccess=false for empty policy")
	}
}

// Cross-account write access tests

func TestCrossAccountReadOnly(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.HasExternalAccess {
		t.Error("expected HasExternalAccess=true")
	}
	if result.HasExternalWrite {
		t.Error("expected HasExternalWrite=false for read-only access")
	}
}

func TestCrossAccountWriteAccess(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": ["s3:GetObject", "s3:PutObject"],
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.HasExternalAccess {
		t.Error("expected HasExternalAccess=true")
	}
	if !result.HasExternalWrite {
		t.Error("expected HasExternalWrite=true for PutObject")
	}
}

func TestCrossAccountWildcard(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.HasExternalWrite {
		t.Error("expected HasExternalWrite=true for s3:*")
	}
}

func TestCrossAccountNoExternal(t *testing.T) {
	// Public principal — no external account ARNs
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": ["s3:PutObject", "s3:DeleteObject"],
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.HasExternalAccess {
		t.Error("expected HasExternalAccess=false for public principal")
	}
	if result.HasExternalWrite {
		t.Error("expected HasExternalWrite=false when no external accounts")
	}
}

func TestCrossAccountPutWildcard(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:role/deployer"},
			"Action": ["s3:Put*"],
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.HasExternalAccess {
		t.Error("expected HasExternalAccess=true")
	}
	if !result.HasExternalWrite {
		t.Error("expected HasExternalWrite=true for s3:Put* wildcard")
	}
}

// Condition analysis tests

func TestAnalyzeConditionIPAddress(t *testing.T) {
	condition := map[string]any{
		"IpAddress": map[string]any{
			"aws:SourceIp": "10.0.0.0/8",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasIPCondition {
		t.Error("expected HasIPCondition=true for IpAddress/aws:SourceIp")
	}
	if result.HasVPCCondition {
		t.Error("expected HasVPCCondition=false")
	}
}

func TestAnalyzeConditionNotIPAddress(t *testing.T) {
	condition := map[string]any{
		"NotIpAddress": map[string]any{
			"aws:SourceIp": "0.0.0.0/0",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasIPCondition {
		t.Error("expected HasIPCondition=true for NotIpAddress/aws:SourceIp")
	}
}

func TestAnalyzeConditionVPCEndpoint(t *testing.T) {
	condition := map[string]any{
		"StringEquals": map[string]any{
			"aws:sourceVpce": "vpce-1a2b3c4d",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true for StringEquals/aws:sourceVpce")
	}
	if result.HasIPCondition {
		t.Error("expected HasIPCondition=false")
	}
}

func TestAnalyzeConditionSourceVPC(t *testing.T) {
	condition := map[string]any{
		"StringEquals": map[string]any{
			"aws:SourceVpc": "vpc-abc123",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true for StringEquals/aws:SourceVpc")
	}
}

func TestAnalyzeConditionPrincipalOrgID(t *testing.T) {
	condition := map[string]any{
		"StringEquals": map[string]any{
			"aws:PrincipalOrgID": "o-abc123",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasOrgCondition {
		t.Error("expected HasOrgCondition=true for StringEquals/aws:PrincipalOrgID")
	}
	if result.HasIPCondition || result.HasVPCCondition {
		t.Error("expected IP and VPC conditions to be false")
	}
}

func TestAnalyzeConditionPrincipalOrgIDStringEqualsIgnoreCase(t *testing.T) {
	condition := map[string]any{
		"StringEqualsIgnoreCase": map[string]any{
			"aws:PrincipalOrgID": "o-abc123",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasOrgCondition {
		t.Error("expected HasOrgCondition=true for StringEqualsIgnoreCase/aws:PrincipalOrgID")
	}
}

func TestAnalyzeConditionForAnyValueSourceVPCE(t *testing.T) {
	condition := map[string]any{
		"ForAnyValue:StringEquals": map[string]any{
			"aws:sourceVpce": "vpce-1a2b3c4d",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true for ForAnyValue:StringEquals/aws:sourceVpce")
	}
}

func TestAnalyzeConditionForAnyValueStringEqualsIfExists(t *testing.T) {
	condition := map[string]any{
		"ForAnyValue:StringEqualsIfExists": map[string]any{
			"aws:sourceVpce": "vpce-1a2b3c4d",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true for ForAnyValue:StringEqualsIfExists/aws:sourceVpce")
	}
}

func TestAnalyzeConditionNestedSetOperatorsIfExists(t *testing.T) {
	condition := map[string]any{
		"ForAnyValue:ForAllValues:ArnLikeIfExists": map[string]any{
			"aws:SourceVpc": "vpc-*",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true for nested set operators with IfExists")
	}
}

func TestAnalyzeConditionMultiple(t *testing.T) {
	condition := map[string]any{
		"IpAddress": map[string]any{
			"aws:SourceIp": "10.0.0.0/8",
		},
		"StringEquals": map[string]any{
			"aws:sourceVpce":     "vpce-1a2b3c4d",
			"aws:PrincipalOrgID": "o-abc123",
		},
	}
	result := analyzeCondition(condition)

	if !result.HasIPCondition {
		t.Error("expected HasIPCondition=true")
	}
	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true")
	}
	if !result.HasOrgCondition {
		t.Error("expected HasOrgCondition=true")
	}
}

func TestAnalyzeConditionNoCondition(t *testing.T) {
	result := analyzeCondition(nil)

	if result.HasIPCondition || result.HasVPCCondition || result.HasOrgCondition {
		t.Error("expected all conditions false for nil")
	}
}

func TestAnalyzeConditionIrrelevantKeys(t *testing.T) {
	condition := map[string]any{
		"Bool": map[string]any{
			"aws:SecureTransport": "false",
		},
	}
	result := analyzeCondition(condition)

	if result.HasIPCondition || result.HasVPCCondition || result.HasOrgCondition {
		t.Error("expected all network conditions false for SecureTransport-only condition")
	}
}

func TestAnalyzeConditionEmptyMap(t *testing.T) {
	condition := map[string]any{}
	result := analyzeCondition(condition)

	if result.HasIPCondition || result.HasVPCCondition || result.HasOrgCondition {
		t.Error("expected all conditions false for empty map")
	}
}

func TestAnalyzeConditionMalformed(t *testing.T) {
	// Condition is a string instead of a map — should not panic
	result := analyzeCondition("not-a-map")

	if result.HasIPCondition || result.HasVPCCondition || result.HasOrgCondition {
		t.Error("expected all conditions false for malformed condition")
	}
}

// Effective network scope tests

func TestEffectiveNetworkScopePublicNoCondition(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.EffectiveNetworkScope != kernel.NetworkScopePublic {
		t.Errorf("expected EffectiveNetworkScope='public', got %q", result.EffectiveNetworkScope)
	}
	if !result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=true for unconditioned public principal")
	}
}

func TestEffectiveNetworkScopeIPRestricted(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"IpAddress": {
					"aws:SourceIp": "10.0.0.0/8"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.EffectiveNetworkScope != kernel.NetworkScopeIPRestricted {
		t.Errorf("expected EffectiveNetworkScope='ip-restricted', got %q", result.EffectiveNetworkScope)
	}
	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false when IP-conditioned")
	}
	if !result.HasIPCondition {
		t.Error("expected HasIPCondition=true")
	}
}

func TestEffectiveNetworkScopeVPCRestricted(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringEquals": {
					"aws:sourceVpce": "vpce-1a2b3c4d"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.EffectiveNetworkScope != kernel.NetworkScopeVPCRestricted {
		t.Errorf("expected EffectiveNetworkScope='vpc-restricted', got %q", result.EffectiveNetworkScope)
	}
	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false when VPC-conditioned")
	}
	if !result.HasVPCCondition {
		t.Error("expected HasVPCCondition=true")
	}
}

func TestEffectiveNetworkScopeOrgRestricted(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringEquals": {
					"aws:PrincipalOrgID": "o-abc123"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.EffectiveNetworkScope != kernel.NetworkScopeOrgRestricted {
		t.Errorf("expected EffectiveNetworkScope='org-restricted', got %q", result.EffectiveNetworkScope)
	}
	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false when Org-conditioned")
	}
}

func TestEffectiveNetworkScopeSpecificARNNoScope(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.EffectiveNetworkScope != kernel.NetworkScopeUnknown {
		t.Errorf("expected empty EffectiveNetworkScope for specific ARN, got %q", result.EffectiveNetworkScope)
	}
}

func TestEffectiveNetworkScopeWeakestLink(t *testing.T) {
	// Two statements: one public (no condition), one VPC-restricted.
	// Overall scope should be "public" (weakest link).
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "PublicRead",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*"
			},
			{
				"Sid": "VPCList",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:ListBucket",
				"Resource": "arn:aws:s3:::my-bucket",
				"Condition": {
					"StringEquals": {
						"aws:sourceVpce": "vpce-1a2b3c4d"
					}
				}
			}
		]
	}`

	result := mustAssess(t, policy)

	if result.EffectiveNetworkScope != kernel.NetworkScopePublic {
		t.Errorf("expected EffectiveNetworkScope='public' (weakest link), got %q", result.EffectiveNetworkScope)
	}
	if !result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=true from the unconditioned statement")
	}
	if result.AllowsPublicList {
		t.Error("expected AllowsPublicList=false because List statement is VPC-conditioned")
	}
}

func TestEffectiveNetworkScopeVPCGetObjectSuppressesPublicRead(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringEquals": {
					"aws:sourceVpce": "vpce-1a2b3c4d"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false for VPC-conditioned GetObject")
	}
}

func TestEffectiveNetworkScopeIPListBucketSuppressesPublicList(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:ListBucket",
			"Resource": "arn:aws:s3:::my-bucket",
			"Condition": {
				"IpAddress": {
					"aws:SourceIp": "192.168.1.0/24"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicList {
		t.Error("expected AllowsPublicList=false for IP-conditioned ListBucket")
	}
}

// Authenticated principal tests

func TestAnalyzePolicyAuthenticatedRead(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::*:root"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsAuthenticatedRead {
		t.Error("expected AllowsAuthenticatedRead=true for arn:aws:iam::*:root")
	}
	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false for authenticated-only principal")
	}
}

func TestAnalyzePolicyAuthenticatedWrite(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::*:root"},
			"Action": ["s3:PutObject", "s3:ListBucket"],
			"Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsAuthenticatedWrite {
		t.Error("expected AllowsAuthenticatedWrite=true")
	}
	if !result.AllowsAuthenticatedList {
		t.Error("expected AllowsAuthenticatedList=true")
	}
	if result.AllowsPublicWrite {
		t.Error("expected AllowsPublicWrite=false for authenticated-only")
	}
}

func TestAnalyzePolicyAuthenticatedPrincipalArray(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": ["arn:aws:iam::*:root"]},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsAuthenticatedRead {
		t.Error("expected AllowsAuthenticatedRead=true for AWS array with arn:aws:iam::*:root")
	}
}

func TestAnalyzePolicySpecificAccountNotAuthenticated(t *testing.T) {
	// A specific account ARN is NOT the authenticated-users pattern
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsAuthenticatedRead {
		t.Error("expected AllowsAuthenticatedRead=false for specific account ARN")
	}
	if result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=false for specific account ARN")
	}
}

func TestEffectiveNetworkScopeSecureTransportNotNetworkCondition(t *testing.T) {
	// SecureTransport is NOT a network scoping condition — should still flag as public
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"Bool": {
					"aws:SecureTransport": "true"
				}
			}
		}]
	}`

	result := mustAssess(t, policy)

	if result.EffectiveNetworkScope != kernel.NetworkScopePublic {
		t.Errorf("expected EffectiveNetworkScope='public' for SecureTransport-only condition, got %q", result.EffectiveNetworkScope)
	}
	if !result.AllowsPublicRead {
		t.Error("expected AllowsPublicRead=true — SecureTransport does not restrict network scope")
	}
}

// Gap 1: Public ACL modification (PutBucketAcl) tests

func TestAnalyzePolicyPublicPutBucketAcl(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:PutBucketAcl",
			"Resource": "arn:aws:s3:::my-bucket"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicACLWrite {
		t.Error("expected AllowsPublicACLWrite=true for public PutBucketAcl")
	}
	if result.AllowsPublicACLRead {
		t.Error("expected AllowsPublicACLRead=false for PutBucketAcl only")
	}
}

func TestAnalyzePolicyPublicPutObjectAcl(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:PutObjectAcl",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicACLWrite {
		t.Error("expected AllowsPublicACLWrite=true for public PutObjectAcl")
	}
}

func TestAnalyzePolicyAuthenticatedPutBucketAcl(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::*:root"},
			"Action": "s3:PutBucketAcl",
			"Resource": "arn:aws:s3:::my-bucket"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsAuthenticatedACLWrite {
		t.Error("expected AllowsAuthenticatedACLWrite=true for authenticated PutBucketAcl")
	}
	if result.AllowsPublicACLWrite {
		t.Error("expected AllowsPublicACLWrite=false for authenticated-only principal")
	}
}

// Gap 2: Public ACL readability (GetBucketAcl) tests

func TestAnalyzePolicyPublicGetBucketAcl(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetBucketAcl",
			"Resource": "arn:aws:s3:::my-bucket"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicACLRead {
		t.Error("expected AllowsPublicACLRead=true for public GetBucketAcl")
	}
	if result.AllowsPublicACLWrite {
		t.Error("expected AllowsPublicACLWrite=false for GetBucketAcl only")
	}
}

func TestAnalyzePolicyPublicGetObjectAcl(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObjectAcl",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicACLRead {
		t.Error("expected AllowsPublicACLRead=true for public GetObjectAcl")
	}
}

func TestAnalyzePolicyAuthenticatedGetBucketAcl(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::*:root"},
			"Action": "s3:GetBucketAcl",
			"Resource": "arn:aws:s3:::my-bucket"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsAuthenticatedACLRead {
		t.Error("expected AllowsAuthenticatedACLRead=true for authenticated GetBucketAcl")
	}
	if result.AllowsPublicACLRead {
		t.Error("expected AllowsPublicACLRead=false for authenticated-only principal")
	}
}

// Wildcard actions should set ACL flags

func TestAnalyzePolicyWildcardSetsACLFlags(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "*"
		}]
	}`

	result := mustAssess(t, policy)

	if !result.AllowsPublicACLWrite {
		t.Error("expected AllowsPublicACLWrite=true for s3:* wildcard")
	}
	if !result.AllowsPublicACLRead {
		t.Error("expected AllowsPublicACLRead=true for s3:* wildcard")
	}
}

// GetObject should NOT set ACL read flag

func TestAnalyzePolicyGetObjectDoesNotSetACLRead(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	result := mustAssess(t, policy)

	if result.AllowsPublicACLRead {
		t.Error("expected AllowsPublicACLRead=false for GetObject (not GetBucketAcl)")
	}
}
