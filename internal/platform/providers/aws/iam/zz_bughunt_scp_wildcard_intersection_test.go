package iam

import "testing"

// TestBugHunt_ScpFullAccessIntersection proves that an SCP hierarchy
// containing the AWS-default FullAWSAccess policy ({"Action":"*","Resource":"*"})
// alongside a more specific SCP yields the SPECIFIC actions as the ceiling —
// not an empty (deny-everything) ceiling.
//
// collectSCPCeiling folds the hierarchy with intersectGrants, which computed
// the intersection by EXACT (action,resource) pair equality. AWS Organizations
// attaches FullAWSAccess ("*"/"*") at every level by default, so a real
// hierarchy is almost always [FullAWSAccess, <specific SCP>]. Exact-pair
// intersection finds no common literal pair between ("*","*") and
// ("s3:GetObject","*"), collapses the ceiling to empty, and SCP-blocks EVERY
// action — reporting that the principal has zero effective permissions. That
// nullifies IAM analysis for essentially every org-managed account.
//
// The correct intersection honors wildcard subsumption: "*"/"*" allows
// everything, so FullAWSAccess ∩ {s3:GetObject} = {s3:GetObject}. The
// principal's s3:GetObject grant must survive as EffectiveAllow, not land in
// SCPBlocked.
//
// (Sibling Test_RedGate_ScpEmptyIntersection pins the opposite, still-correct
// case: two genuinely non-overlapping specific SCPs DO intersect to empty.)
func TestBugHunt_ScpFullAccessIntersection(t *testing.T) {
	t.Parallel()

	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123456789012:role/r",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			// AWS-default FullAWSAccess (root) ...
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
			// ... plus a more specific SCP that still permits s3:GetObject.
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
		},
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}

	for _, a := range result.SCPBlocked {
		if a == "s3:GetObject" {
			t.Fatalf("FullAWSAccess ∩ {s3:GetObject} must permit s3:GetObject, "+
				"but it was SCP-blocked (exact-pair intersection collapsed the "+
				"ceiling to empty); SCPBlocked=%v EffectiveAllow=%+v",
				result.SCPBlocked, result.EffectiveAllow)
		}
	}

	found := false
	for _, g := range result.EffectiveAllow {
		if g.Action == "s3:GetObject" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected s3:GetObject in EffectiveAllow under "+
			"[FullAWSAccess, {s3:GetObject}] SCPs, got EffectiveAllow=%+v SCPBlocked=%v",
			result.EffectiveAllow, result.SCPBlocked)
	}
}
