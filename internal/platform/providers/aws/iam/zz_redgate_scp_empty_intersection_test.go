package iam

import "testing"

// Test_RedGate_ScpEmptyIntersection asserts the CORRECT behavior
// documented at resolve.go:197 — "an empty intersection means
// everything is denied" — and at resolve.go:209-211 where an empty
// running SCP intersection is described as "a deny-by-omission ...
// the SCP chain's strongest possible verdict" (DENY EVERYTHING).
//
// Two SCPs whose Allow sets share no common (action,resource) pair
// intersect to the empty set. collectSCPCeiling returns nil for that
// case, and matchesCeiling treats a nil ceiling as "no ceiling =
// everything passes" — the EXACT OPPOSITE of the documented intent.
//
// Trigger from the bug report: a role with identity Allow
// s3:GetObject on *, under an SCP hierarchy of {Allow s3:GetObject}
// and {Allow ec2:DescribeInstances}. The intersection is empty, so
// the SCP chain must block everything: s3:GetObject must be reported
// in SCPBlocked and must NOT appear in EffectiveAllow.
func Test_RedGate_ScpEmptyIntersection(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during Resolve: %v", r)
		}
	}()

	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123:role/r",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
		},
		SCPPresent: true,
		SCPHierarchy: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}`),
		},
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}

	// The empty SCP intersection denies everything. s3:GetObject must
	// be SCP-blocked, not effectively allowed.
	for _, g := range result.EffectiveAllow {
		if g.Action == "s3:GetObject" {
			t.Fatalf("empty SCP intersection must DENY everything: "+
				"s3:GetObject leaked into EffectiveAllow=%+v (want it in SCPBlocked)",
				result.EffectiveAllow)
		}
	}

	blocked := false
	for _, a := range result.SCPBlocked {
		if a == "s3:GetObject" {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("empty SCP intersection must DENY everything: "+
			"expected s3:GetObject in SCPBlocked, got SCPBlocked=%v EffectiveAllow=%+v",
			result.SCPBlocked, result.EffectiveAllow)
	}
}
