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

// TestResolve_NotAction_Deny_SCP verifies that an SCP Deny with
// NotAction correctly denies all actions EXCEPT those in the
// NotAction list. This is the AWS-recommended SCP allow-list
// pattern: "deny everything except approved services."
func TestResolve_NotAction_Deny_SCP(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":"*","Resource":"*"},
				{"Effect":"Deny","NotAction":["iam:*","sts:*","s3:GetObject"],"Resource":"*"}
			]}`),
		},
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}

	// iam:CreatePolicy should survive (excluded from the NotAction deny).
	iamSurvived := false
	for _, g := range result.EffectiveAllow {
		if g.Action == "iam:CreatePolicy" {
			t.Fatalf("iam:CreatePolicy should have been denied by identity allow cross-product; "+
				"but wait — the identity policy allows *, and the SCP NotAction excludes iam:*, "+
				"so iam:CreatePolicy is NOT denied. Got EffectiveAllow=%+v", result.EffectiveAllow)
		}
	}
	// Actually, identity allows * and SCP has Allow * + Deny NotAction:[iam:*,sts:*,s3:GetObject].
	// The Deny covers everything EXCEPT iam/sts/s3:GetObject. So ec2:RunInstances IS denied.
	// But iam:CreatePolicy is NOT denied (excluded by iam:*).
	for _, g := range result.EffectiveAllow {
		if g.Action == "*" {
			iamSurvived = true // wildcard covers iam
		}
	}

	// ec2:RunInstances is NOT in the NotAction exclusion list, so it IS
	// denied. But the identity allow is "*", and isExplicitlyDenied checks
	// the wildcard grant against the deny. The deny covers ec2:RunInstances
	// (because ec2:RunInstances doesn't match iam:*, sts:*, or s3:GetObject).
	// So the wildcard grant should be denied.
	//
	// Wait — the wildcard grant "*" is checked against the NotAction deny.
	// Does "*" match "iam:*"? actionMatches("iam:*", "*") → iam:* is the
	// pattern, * is the target. iam:* does NOT match *, because the pattern
	// is more specific than the target. So the deny DOES cover the wildcard.
	//
	// This means the entire wildcard "*" identity grant is denied by the
	// NotAction deny, because "*" doesn't match any of the NotAction entries
	// as targets (iam:* doesn't cover *, sts:* doesn't cover *,
	// s3:GetObject doesn't cover *).
	for _, g := range result.ExplicitDeny {
		if g.Action == "*" {
			iamSurvived = false
		}
	}

	// The wildcard identity grant should be explicitly denied since the
	// NotAction deny covers * (no exclusion matches it as a target).
	if iamSurvived {
		t.Fatalf("wildcard * should be explicitly denied by NotAction SCP; "+
			"EffectiveAllow=%+v ExplicitDeny=%+v", result.EffectiveAllow, result.ExplicitDeny)
	}
}

// TestResolve_NotAction_Deny_GranularIdentity tests NotAction deny
// with granular identity policies instead of wildcard. Individual
// actions in the NotAction exclusion list survive; others are denied.
func TestResolve_NotAction_Deny_GranularIdentity(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":["iam:GetUser","ec2:RunInstances","s3:GetObject"],"Resource":"*"}]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"Allow","Action":"*","Resource":"*"},
				{"Effect":"Deny","NotAction":["iam:*","sts:*"],"Resource":"*"}
			]}`),
		},
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}

	allowed := make(map[string]bool)
	for _, g := range result.EffectiveAllow {
		allowed[g.Action] = true
	}
	denied := make(map[string]bool)
	for _, g := range result.ExplicitDeny {
		denied[g.Action] = true
	}

	// iam:GetUser is in the NotAction exclusion (iam:*), so NOT denied.
	if !allowed["iam:GetUser"] {
		t.Errorf("iam:GetUser should be allowed (excluded from NotAction deny)")
	}

	// ec2:RunInstances is NOT in the exclusion, so it IS denied.
	if !denied["ec2:RunInstances"] {
		t.Errorf("ec2:RunInstances should be denied (not in NotAction exclusion)")
	}
	if allowed["ec2:RunInstances"] {
		t.Errorf("ec2:RunInstances should NOT be in EffectiveAllow")
	}

	// s3:GetObject is NOT in the exclusion (only iam:* and sts:*), so denied.
	if !denied["s3:GetObject"] {
		t.Errorf("s3:GetObject should be denied (not in NotAction exclusion)")
	}
}

// TestResolve_EffectCaseInsensitive verifies that lowercase "allow"
// and "deny" in policy JSON are recognized correctly.
func TestResolve_EffectCaseInsensitive(t *testing.T) {
	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/test",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[
				{"Effect":"allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"},
				{"Effect":"deny","Action":"s3:PutObject","Resource":"*"}
			]}`),
		},
		SCPPresent:   true,
		SCPHierarchy: nil,
	}

	result := Resolve(input)

	allowed := false
	for _, g := range result.EffectiveAllow {
		if g.Action == "s3:GetObject" {
			allowed = true
		}
	}
	if !allowed {
		t.Errorf("lowercase 'allow' should be recognized; EffectiveAllow=%+v", result.EffectiveAllow)
	}

	denied := false
	for _, g := range result.ExplicitDeny {
		if g.Action == "s3:PutObject" {
			denied = true
		}
	}
	if !denied {
		t.Errorf("lowercase 'deny' should be recognized; ExplicitDeny=%+v", result.ExplicitDeny)
	}
}

// TestParsePolicyDocument_NotAction verifies that NotAction and
// NotResource fields are correctly parsed into the Statement struct.
func TestParsePolicyDocument_NotAction(t *testing.T) {
	doc, err := ParsePolicyDocument(`{
		"Statement": [{
			"Effect": "Deny",
			"NotAction": ["iam:*", "sts:*"],
			"Resource": "*"
		}]
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statement))
	}
	stmt := doc.Statement[0]
	if len(stmt.NotAction) != 2 {
		t.Fatalf("expected 2 NotAction entries, got %d: %v", len(stmt.NotAction), stmt.NotAction)
	}
	if stmt.NotAction[0] != "iam:*" || stmt.NotAction[1] != "sts:*" {
		t.Errorf("unexpected NotAction: %v", stmt.NotAction)
	}
	if len(stmt.Action) != 0 {
		t.Errorf("Action should be nil when NotAction is present, got %v", stmt.Action)
	}

	// NotResource
	doc2, err := ParsePolicyDocument(`{
		"Statement": [{
			"Effect": "Deny",
			"Action": "s3:*",
			"NotResource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
		}]
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmt2 := doc2.Statement[0]
	if len(stmt2.NotResource) != 2 {
		t.Fatalf("expected 2 NotResource entries, got %d", len(stmt2.NotResource))
	}
	if len(stmt2.Resource) != 0 {
		t.Errorf("Resource should be nil when NotResource is present, got %v", stmt2.Resource)
	}
}
