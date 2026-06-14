package iam

import "testing"

// TestBugHunt_AdminClassifiedWithLowercaseAction proves that an identity
// policy granting an admin-equivalent IAM action in non-canonical lowercase
// ("iam:createpolicy" on "*") is still classified as admin.
//
// classifyPrivilege compared each effective action against an exact-case set
// of admin/elevated indicators ("iam:CreatePolicy", "iam:PassRole", ...).
// IAM action names are case-insensitive in AWS, and actions are NOT case-
// normalized during resolution (normalizeStringOrAny only fixes the
// string-vs-array shape). So a principal whose policy grants
// "iam:createpolicy" — which AWS honors as full IAM-admin — was classified
// PrivilegeLevelLimited instead of PrivilegeLevelAdmin. That is a privilege-
// escalation false negative: a genuinely admin principal is reported as
// low-privilege, and an attacker can dodge the classifier by lowercasing the
// action.
//
// Correct behavior: the admin indicator matches case-insensitively.
func TestBugHunt_AdminClassifiedWithLowercaseAction(t *testing.T) {
	t.Parallel()

	input := ResolutionInput{
		PrincipalARN: "arn:aws:iam::123456789012:role/r",
		IdentityPolicies: []PolicyDocument{
			mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"iam:createpolicy","Resource":"*"}]}`),
		},
		SCPPresent:   true,
		SCPHierarchy: nil, // no org — no SCP ceiling
	}

	result := Resolve(input)
	if result.Incomplete {
		t.Fatalf("unexpected incomplete: %v", result.IncompleteReasons)
	}

	if result.PrivilegeLevel != PrivilegeLevelAdmin {
		t.Errorf(`expected PrivilegeLevelAdmin for an identity grant of `+
			`"iam:createpolicy" (lowercase) on "*", got %q; AWS matches IAM `+
			`action names case-insensitively, so this principal IS admin`,
			result.PrivilegeLevel)
	}
}
