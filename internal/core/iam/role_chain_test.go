package iam

import (
	"testing"
)

func buildResolvedIndex(entries map[string]ResolvedPermissions) map[string]*ResolvedPermissions {
	idx := make(map[string]*ResolvedPermissions, len(entries))
	for k, v := range entries {
		idx[k] = &v
	}
	return idx
}

func trustDoc(t *testing.T, principals ...string) *PolicyDocument {
	t.Helper()
	var resources string
	if len(principals) == 1 {
		resources = `"` + principals[0] + `"`
	} else {
		resources = `[`
		for i, p := range principals {
			if i > 0 {
				resources += ","
			}
			resources += `"` + p + `"`
		}
		resources += `]`
	}
	doc := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":`+resources+`}]}`)
	return &doc
}

func TestResolveChains_DirectAssumption(t *testing.T) {
	input := RoleChainInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			"arn:aws:iam::123:role/dev": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::123:role/admin"},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			"arn:aws:iam::123:role/admin": {
				EffectiveAllow: []ActionGrant{
					{Action: "*", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			"arn:aws:iam::123:role/admin": trustDoc(t, "arn:aws:iam::123:role/dev"),
		},
	}

	chains := ResolveChains(input)
	if len(chains) == 0 {
		t.Fatal("expected at least one chain")
	}
	if !HasTransitiveAdmin(chains) {
		t.Fatal("expected transitive admin access")
	}
	if chains[0].TransitiveLevel != PrivilegeLevelAdmin {
		t.Fatalf("expected admin level, got %s", chains[0].TransitiveLevel)
	}
}

func TestResolveChains_TwoHop(t *testing.T) {
	input := RoleChainInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			"arn:aws:iam::123:role/dev": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::123:role/pipeline"},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			"arn:aws:iam::123:role/pipeline": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::123:role/admin"},
					{Action: "s3:GetObject", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelStandard,
			},
			"arn:aws:iam::123:role/admin": {
				EffectiveAllow: []ActionGrant{
					{Action: "*", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			"arn:aws:iam::123:role/pipeline": trustDoc(t, "arn:aws:iam::123:role/dev"),
			"arn:aws:iam::123:role/admin":    trustDoc(t, "arn:aws:iam::123:role/pipeline"),
		},
	}

	chains := ResolveChains(input)
	if !HasTransitiveAdmin(chains) {
		t.Fatal("expected transitive admin via 2-hop chain")
	}
	if MaxDepth(chains) < 2 {
		t.Fatalf("expected max depth >= 2, got %d", MaxDepth(chains))
	}
}

func TestResolveChains_CycleDetection(t *testing.T) {
	input := RoleChainInput{
		PrincipalARN: "arn:aws:iam::123:role/a",
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			"arn:aws:iam::123:role/a": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::123:role/b"},
				},
			},
			"arn:aws:iam::123:role/b": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::123:role/a"},
				},
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			"arn:aws:iam::123:role/a": trustDoc(t, "arn:aws:iam::123:role/b"),
			"arn:aws:iam::123:role/b": trustDoc(t, "arn:aws:iam::123:role/a"),
		},
	}

	chains := ResolveChains(input)
	hasCycle := false
	for _, c := range chains {
		if c.TerminationReason == ChainTerminatedCycle {
			hasCycle = true
		}
	}
	if !hasCycle {
		t.Fatal("expected cycle detection")
	}
}

func TestResolveChains_NotInSnapshot(t *testing.T) {
	input := RoleChainInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			"arn:aws:iam::123:role/dev": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::999:role/external"},
				},
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{},
	}

	chains := ResolveChains(input)
	hasNotInSnapshot := false
	for _, c := range chains {
		if c.TerminationReason == ChainTerminatedNotInSnapshot {
			hasNotInSnapshot = true
		}
	}
	if !hasNotInSnapshot {
		t.Fatal("expected not-in-snapshot termination")
	}
}

func TestResolveChains_TrustPolicyRejectsAssumption(t *testing.T) {
	input := RoleChainInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			"arn:aws:iam::123:role/dev": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::123:role/admin"},
				},
			},
			"arn:aws:iam::123:role/admin": {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			// admin role only trusts pipeline, not dev
			"arn:aws:iam::123:role/admin": trustDoc(t, "arn:aws:iam::123:role/pipeline"),
		},
	}

	chains := ResolveChains(input)
	if HasTransitiveAdmin(chains) {
		t.Fatal("expected NO transitive admin — trust policy rejects dev")
	}
}

func TestResolveChains_CrossAccountHop(t *testing.T) {
	input := RoleChainInput{
		PrincipalARN: "arn:aws:iam::123:role/dev",
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			"arn:aws:iam::123:role/dev": {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: "arn:aws:iam::999:role/cross-admin"},
				},
			},
			"arn:aws:iam::999:role/cross-admin": {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			"arn:aws:iam::999:role/cross-admin": trustDoc(t, "arn:aws:iam::123:role/dev"),
		},
	}

	chains := ResolveChains(input)
	if !HasTransitiveAdmin(chains) {
		t.Fatal("expected transitive admin via cross-account")
	}
	hasCrossAccount := false
	for _, c := range chains {
		for _, hop := range c.Hops {
			if hop.IsCrossAccount {
				hasCrossAccount = true
			}
		}
	}
	if !hasCrossAccount {
		t.Fatal("expected cross-account hop flag")
	}
}
