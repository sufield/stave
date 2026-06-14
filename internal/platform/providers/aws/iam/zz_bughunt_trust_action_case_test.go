package iam

import "testing"

// TestBugHunt_TrustPolicyAssumeActionCaseInsensitive proves that a role's
// trust policy whose assume action is written in non-canonical casing
// ("sts:assumerole") still admits the assumer.
//
// trustPolicyAllows checked the trust-policy action against an inline,
// exact-case set {"sts:AssumeRole", "sts:*", "*"}. AWS matches IAM action
// names case-insensitively, so a trust policy that grants "sts:assumerole"
// admits the principal identically — but the exact-case check returned
// false, so trustAllowsAssumer reported the assumption as not reciprocated
// and resolveChainRecursive dropped the hop. That is a privilege-escalation
// false negative: a real assume edge becomes invisible to the chain walker,
// and an attacker can hide the path simply by lowercasing the action.
//
// The grant side already uses isAssumeRoleAction (case-insensitive and
// inclusive of the federated assume verbs); the trust side must use the same
// predicate. Correct behavior: the lowercase action is recognized and the
// principal is admitted.
func TestBugHunt_TrustPolicyAssumeActionCaseInsensitive(t *testing.T) {
	t.Parallel()

	const caller = "arn:aws:iam::123456789012:role/caller"

	// Trust policy in the legacy/test-fixture shape: the trusted principal
	// is carried in Resource. Action uses non-canonical lowercase casing.
	doc := mustParse(t, `{"Statement":[{
		"Effect":"Allow",
		"Action":"sts:assumerole",
		"Resource":"`+caller+`"
	}]}`)

	if !trustPolicyAllows(&doc, caller) {
		t.Errorf(`expected trustPolicyAllows=true for a trust policy granting `+
			`"sts:assumerole" (lowercase) to %q; AWS matches IAM action names `+
			`case-insensitively, so this role DOES trust the caller`, caller)
	}
}
