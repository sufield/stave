package iam

import (
	"testing"
)

func mustParse(t *testing.T, raw string) PolicyDocument {
	t.Helper()
	doc, err := ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("ParsePolicyDocument: %v", err)
	}
	return doc
}

func TestResolve_AdminAllowed(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/admin",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		},
		SCPPresent:   true,
		SCPHierarchy: nil, // no org
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("expected complete, got incomplete: %v", result.IncompleteReasons)
	}
	if result.PrivilegeLevel != PrivilegeLevelAdmin {
		t.Fatalf("expected admin, got %s", result.PrivilegeLevel)
	}
	if !result.IsAdmin {
		t.Fatal("expected IsAdmin true")
	}
}

func TestResolve_AdminBlockedBySCP(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/constrained",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
		},
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}
	// SCP only allows s3:*, so iam:* should be blocked
	if result.PrivilegeLevel == PrivilegeLevelAdmin {
		t.Fatal("expected non-admin — SCP should block admin actions")
	}
	if len(result.SCPBlocked) == 0 {
		t.Fatal("expected SCP to block some actions")
	}
}

func TestResolve_AdminBlockedByBoundary(t *testing.T) {
	boundary := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/bounded",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		},
		SCPPresent:      true,
		SCPHierarchy:    nil, // no org
		BoundaryPresent: true,
		BoundaryPolicy:  &boundary,
	}

	result := Resolve(input)
	if result.PrivilegeLevel == PrivilegeLevelAdmin {
		t.Fatal("expected non-admin — boundary should constrain")
	}
	if len(result.BoundaryBlocked) == 0 {
		t.Fatal("expected boundary to block some actions")
	}
	if !result.BoundaryEffective {
		t.Fatal("expected boundary to be effective")
	}
}

func TestResolve_TriviallyBroadBoundary(t *testing.T) {
	boundary := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/broad-boundary",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
		},
		SCPPresent:      true,
		SCPHierarchy:    nil,
		BoundaryPresent: true,
		BoundaryPolicy:  &boundary,
	}

	result := Resolve(input)
	// Boundary allows everything — it blocks nothing
	if result.BoundaryEffective {
		t.Fatal("expected boundary NOT effective — it allows everything")
	}
}

func TestResolve_ExplicitDenyOverridesAllow(t *testing.T) {
	// Deny on a specific action blocks that specific allow.
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/denied",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":["s3:GetObject","iam:CreatePolicy"],"Resource":"*"},
				{"Effect":"Deny","Action":"iam:CreatePolicy","Resource":"*"}
			]}`),
		},
		SCPPresent:   true,
		SCPHierarchy: nil,
	}

	result := Resolve(input)
	if len(result.ExplicitDeny) == 0 {
		t.Fatal("expected at least one explicit deny")
	}
	// iam:CreatePolicy should be denied, s3:GetObject should be allowed
	if len(result.EffectiveAllow) != 1 {
		t.Fatalf("expected 1 effective allow (s3:GetObject), got %d", len(result.EffectiveAllow))
	}
	if result.EffectiveAllow[0].Action != "s3:GetObject" {
		t.Fatalf("expected s3:GetObject, got %s", result.EffectiveAllow[0].Action)
	}
	// Should not be admin — iam:CreatePolicy was denied
	if result.PrivilegeLevel == PrivilegeLevelAdmin {
		t.Fatal("expected non-admin — iam:CreatePolicy was denied")
	}
}

func TestResolve_IncompleteWhenSCPAbsent(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/no-scp-data",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
		},
		SCPPresent: false, // absent from snapshot
	}

	result := Resolve(input)
	if !result.Incomplete {
		t.Fatal("expected incomplete when SCP absent")
	}
}

func TestResolve_IncompleteWhenBoundaryDocAbsent(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/missing-boundary-doc",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
		},
		SCPPresent:      true,
		SCPHierarchy:    nil,
		BoundaryPresent: true,
		BoundaryPolicy:  nil, // boundary exists but doc is absent
	}

	result := Resolve(input)
	if !result.Incomplete {
		t.Fatal("expected incomplete when boundary doc absent")
	}
}

func TestResolve_NoBoundary(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/no-boundary",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
		},
		SCPPresent:      true,
		SCPHierarchy:    nil,
		BoundaryPresent: false,
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}
	if result.PrivilegeLevel != PrivilegeLevelLimited {
		t.Fatalf("expected limited, got %s", result.PrivilegeLevel)
	}
}

func TestClassifyPrivilege_None(t *testing.T) {
	level := classifyPrivilege(nil)
	if level != PrivilegeLevelNone {
		t.Fatalf("expected none, got %s", level)
	}
}

func TestClassifyPrivilege_Admin(t *testing.T) {
	grants := []ActionGrant{
		{Action: "iam:CreatePolicy", Resource: "*"},
	}
	level := classifyPrivilege(grants)
	if level != PrivilegeLevelAdmin {
		t.Fatalf("expected admin, got %s", level)
	}
}

func TestClassifyPrivilege_Elevated(t *testing.T) {
	grants := []ActionGrant{
		{Action: "iam:PassRole", Resource: "*"},
	}
	level := classifyPrivilege(grants)
	if level != PrivilegeLevelElevated {
		t.Fatalf("expected elevated, got %s", level)
	}
}
