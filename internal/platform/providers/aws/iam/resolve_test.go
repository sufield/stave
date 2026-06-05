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

// TestResolve_ConditionedDeny_DoesNotCover pins the foundational
// Iter 7 (scoped Deny) detection. A Deny scoped by
// `aws:PrincipalOrgID = o-other-org` does NOT block a principal
// in our org from performing iam:CreatePolicy. Pre-Iter-7 the
// solver credited every Deny matching action+resource as
// universally protective, hiding the attack path.
//
// V1 conservative rule: ANY Condition on a Deny disqualifies it.
// We cannot prove the principal-scoping condition holds for the
// requesting principal, so we surface the path. The Deny is
// still recorded in ExplicitDeny (the catalog can flag the
// scope-narrowed Deny as a posture concern); it just no longer
// suppresses the matching Allow.
func TestResolve_ConditionedDeny_DoesNotCover(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/admin",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":"iam:CreatePolicy","Resource":"*"},
				{"Effect":"Deny","Action":"iam:CreatePolicy","Resource":"*",
				 "Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-our-org"}}}
			]}`),
		},
		SCPPresent:   true,
		SCPHierarchy: nil,
	}

	result := Resolve(input)
	// The scope-narrowed Deny must NOT suppress the Allow:
	// iam:CreatePolicy must surface in EffectiveAllow because the
	// solver cannot prove the deny's PrincipalOrgID condition
	// holds for this principal context.
	hasCreatePolicy := false
	for _, g := range result.EffectiveAllow {
		if g.Action == "iam:CreatePolicy" {
			hasCreatePolicy = true
		}
	}
	if !hasCreatePolicy {
		t.Fatalf("scope-narrowed Deny must NOT suppress Allow; "+
			"got EffectiveAllow=%+v", result.EffectiveAllow)
	}
	// ExplicitDeny tracks denies that COVERED a grant — a
	// scope-narrowed Deny that didn't cover anything is
	// correctly absent here. Posture controls that want to flag
	// the scope-narrowed Deny itself read it from the policy
	// document directly, not from this slot.
	for _, d := range result.ExplicitDeny {
		if d.Action == "iam:CreatePolicy" {
			t.Errorf("scope-narrowed Deny should not appear in ExplicitDeny; got %+v", d)
		}
	}
}

// TestResolve_UnconditionedDeny_StillCovers is the regression
// guard. Iter 7's change must not break the legacy contract
// where an unconditioned Deny suppresses the matching Allow.
// This is the same shape as TestResolve_ExplicitDenyOverridesAllow
// above; restated here so a future revert of Iter 7 trips this
// test directly.
func TestResolve_UnconditionedDeny_StillCovers(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/denied",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":"iam:CreatePolicy","Resource":"*"},
				{"Effect":"Deny","Action":"iam:CreatePolicy","Resource":"*"}
			]}`),
		},
		SCPPresent:   true,
		SCPHierarchy: nil,
	}

	result := Resolve(input)
	for _, g := range result.EffectiveAllow {
		if g.Action == "iam:CreatePolicy" {
			t.Fatalf("unconditioned Deny must still suppress; "+
				"got EffectiveAllow=%+v", result.EffectiveAllow)
		}
	}
}

// TestResolve_ConditionedSCPDeny_DoesNotCover: SCPs are the
// most common production source of scope-narrowed Denies (e.g.,
// an SCP that denies S3 access OUTSIDE the corporate VPC via
// `Condition: StringNotEquals aws:SourceVpce`). For accounts in
// the named VPC, the deny doesn't apply. Pre-Iter-7 those
// accounts were marked as having no S3 access at all.
func TestResolve_ConditionedSCPDeny_DoesNotCover(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}
			]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":"*","Resource":"*"},
				{"Effect":"Deny","Action":"s3:GetObject","Resource":"*",
				 "Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-corp"}}}
			]}`),
		},
	}

	result := Resolve(input)
	hasGet := false
	for _, g := range result.EffectiveAllow {
		if g.Action == "s3:GetObject" {
			hasGet = true
		}
	}
	if !hasGet {
		t.Fatalf("scope-narrowed SCP Deny must NOT suppress Allow; "+
			"got EffectiveAllow=%+v", result.EffectiveAllow)
	}
}

// TestDenyHasNarrowingConditions_Shapes pins the helper: any
// non-empty map narrows; nil and empty map do not; malformed
// non-map shapes are conservatively treated as narrowing.
func TestDenyHasNarrowingConditions_Shapes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want bool
	}{
		{"nil", nil, false},
		{"empty map", map[string]any{}, false},
		{"populated map", map[string]any{
			"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-x"},
		}, true},
		{"string (malformed)", "Allow", true},
		{"slice (malformed)", []any{"x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := denyHasNarrowingConditions(tc.in); got != tc.want {
				t.Errorf("want %v, got %v for %v", tc.want, got, tc.in)
			}
		})
	}
}

// TestCollectSCPCeiling_NonEmptyIntersectionAllowsCommonAction pins the
// other half of the SCP-ceiling contract that
// Test_RedGate_ScpEmptyIntersection does not exercise: when a multi-SCP
// chain has a NON-empty intersection, the common (action,resource) pairs
// must remain allowed and only the non-common ones get blocked.
//
// The empty-intersection redgate test reaches its verdict via the
// post-loop guard (resolve.go:221), so the in-loop early-return
// (resolve.go:207) and the loop's own iteration (resolve.go:204) are
// never pinned by it. This test runs a two-SCP chain whose intersection
// is {s3:GetObject} and asserts that common action stays in
// EffectiveAllow while a single-SCP-only action (ec2:DescribeInstances)
// is SCP-blocked — failing if the ceiling collapses to deny-everything.
func TestCollectSCPCeiling_NonEmptyIntersectionAllowsCommonAction(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during Resolve: %v", r)
		}
	}()

	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/r",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","ec2:DescribeInstances"],"Resource":"*"}]}`),
		},
		SCPPresent: true,
		// Intersection of the two SCP allow sets is {s3:GetObject on *}:
		// ec2:DescribeInstances is allowed by the first SCP only, so it
		// drops out of the ceiling.
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","ec2:DescribeInstances"],"Resource":"*"}]}`),
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`),
		},
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}

	// The common action survives the intersection and must be effectively allowed.
	allowed := false
	for _, g := range result.EffectiveAllow {
		if g.Action == "s3:GetObject" {
			allowed = true
		}
	}
	if !allowed {
		t.Fatalf("non-empty SCP intersection must keep the common action: "+
			"expected s3:GetObject in EffectiveAllow, got EffectiveAllow=%+v SCPBlocked=%v",
			result.EffectiveAllow, result.SCPBlocked)
	}

	// The action allowed by only one SCP is outside the intersection and must be blocked.
	for _, g := range result.EffectiveAllow {
		if g.Action == "ec2:DescribeInstances" {
			t.Fatalf("ec2:DescribeInstances is not in the SCP intersection and must be blocked, "+
				"but leaked into EffectiveAllow=%+v", result.EffectiveAllow)
		}
	}
	blocked := false
	for _, a := range result.SCPBlocked {
		if a == "ec2:DescribeInstances" {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("expected ec2:DescribeInstances in SCPBlocked (outside intersection), got SCPBlocked=%v", result.SCPBlocked)
	}
}
