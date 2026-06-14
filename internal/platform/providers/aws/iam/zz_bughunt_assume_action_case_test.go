package iam

import (
	"slices"
	"testing"
)

// TestBugHunt_AssumeRoleActionCaseInsensitive proves that a trust policy
// whose assume-role Action is written in non-canonical casing
// ("sts:assumerole") is still recognized as granting sts:AssumeRole.
//
// AWS treats IAM action names case-insensitively: {"Action":"sts:assumerole"}
// admits a principal into the role identically to "sts:AssumeRole".
// isAssumeRoleAction (service_trusts.go) compared the raw action against a
// fixed-case switch, so the lowercase form returned false — the service
// principal was never extracted and the role's service trust vanished from
// ServiceTrusts. That is a security false negative: a privilege-escalation
// hop through a service-assumable role goes undetected, and an attacker (or
// merely non-canonical IaC) can evade the chain walker by lowercasing the
// action.
//
// The sibling code is already case-insensitive — Effect is matched with
// strings.EqualFold and service names are lowercased — so this exact-case
// switch was the lone inconsistency. Correct behavior: the action matches
// case-insensitively and lambda.amazonaws.com is extracted.
func TestBugHunt_AssumeRoleActionCaseInsensitive(t *testing.T) {
	t.Parallel()

	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "sts:assumerole",
			"Principal": {"Service": "lambda.amazonaws.com"}
		}]
	}`

	got := parseServicePrincipalsAllowingAssume(trustPolicy)

	if !slices.Contains(got, "lambda.amazonaws.com") {
		t.Errorf("expected lambda.amazonaws.com to be extracted for a trust "+
			`policy with Action "sts:assumerole" (lowercase), got %v; AWS matches `+
			"IAM action names case-insensitively, so this role DOES trust the "+
			"Lambda service", got)
	}
}
