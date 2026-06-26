package iam

import (
	"testing"
)

func TestBugHunt_ResolveChains_ARNCaseInsensitive(t *testing.T) {
	t.Parallel()

	// Principal ARN uses mixed case
	callerARN := "arn:aws:iam::123456789012:role/Caller"
	// Target role ARN uses mixed case in lookup
	targetARN := "arn:aws:iam::123456789012:role/TargetRole"

	resolvedIndex := map[string]*ResolvedPermissions{
		"arn:aws:iam::123456789012:role/caller": {
			EffectiveAllow: []ActionGrant{
				{
					Action:   "sts:AssumeRole",
					Resource: targetARN,
				},
			},
			PrivilegeLevel: PrivilegeLevelLimited,
		},
		"arn:aws:iam::123456789012:role/targetrole": {
			EffectiveAllow: []ActionGrant{
				{
					Action:   "*",
					Resource: "*",
				},
			},
			PrivilegeLevel: PrivilegeLevelAdmin,
		},
	}

	trustPolicies := map[string]*PolicyDocument{
		"arn:aws:iam::123456789012:role/targetrole": {
			Statement: []Statement{
				{
					Effect:   "Allow",
					Action:   []string{"sts:AssumeRole"},
					Resource: []string{"arn:aws:iam::123456789012:role/caller"},
				},
			},
		},
	}

	input := RoleChainInput{
		PrincipalARN:  callerARN,
		ResolvedIndex: resolvedIndex,
		TrustPolicies: trustPolicies,
		AccountID:     "123456789012",
	}

	chains := ResolveChains(input)
	if len(chains) == 0 {
		t.Fatalf("expected to resolve a chain, but got none due to case-sensitivity mismatches")
	}

	found := false
	for _, ch := range chains {
		if (ch.FinalRoleARN == "arn:aws:iam::123456789012:role/targetrole" || ch.FinalRoleARN == targetARN) && ch.TransitiveLevel == PrivilegeLevelAdmin {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find targetrole with Admin level, got chains: %+v", chains)
	}
}
