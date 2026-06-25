package iam

import "testing"

func TestBugHunt_ActionCaseInsensitiveDeny(t *testing.T) {
	t.Parallel()

	// In AWS, IAM actions are case-insensitive.
	// A Deny statement for "s3:GetObject" must block an Allow statement for "S3:GETOBJECT".
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/test-role",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":"S3:GETOBJECT","Resource":"*"},
				{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}
			]}`),
		},
		SCPPresent: true,
	}

	result := Resolve(input)
	if len(result.EffectiveAllow) > 0 {
		t.Errorf("expected S3:GETOBJECT to be explicitly denied, but it was allowed: %v", result.EffectiveAllow)
	}
}

func TestBugHunt_ActionCaseInsensitiveSCP(t *testing.T) {
	t.Parallel()

	// SCP allows "s3:*" (lowercase) and identity policy allows "S3:GetObject".
	// This should be allowed because s3:* matches S3:GetObject case-insensitively.
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/test-role",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"S3:GetObject","Resource":"*"}]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
		},
	}

	result := Resolve(input)
	if len(result.EffectiveAllow) == 0 {
		t.Errorf("expected S3:GetObject to pass through s3:* SCP ceiling, but it was blocked")
	}
}

func TestBugHunt_SCPActionResourceIntersection(t *testing.T) {
	t.Parallel()

	// SCP 1 allows all actions on a specific bucket.
	// SCP 2 allows s3:* on all resources.
	// The intersection of these two SCPs should allow s3:GetObject on the specific bucket.
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/test-role",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/file"}]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::my-bucket/*"}]}`),
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
		},
	}

	result := Resolve(input)
	if len(result.EffectiveAllow) == 0 {
		t.Errorf("expected s3:GetObject on my-bucket/file to be allowed, but it was blocked by SCP ceiling. EffectiveAllow=%v SCPBlocked=%v", result.EffectiveAllow, result.SCPBlocked)
	}
}
