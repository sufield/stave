package iam

import (
	"strings"
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
	var b strings.Builder
	if len(principals) == 1 {
		b.WriteByte('"')
		b.WriteString(principals[0])
		b.WriteByte('"')
	} else {
		b.WriteByte('[')
		for i, p := range principals {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('"')
			b.WriteString(p)
			b.WriteByte('"')
		}
		b.WriteByte(']')
	}
	doc := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":`+b.String()+`}]}`)
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

// trustDocTagConditional builds a trust policy that allows the
// listed principal to assume the role IFF the role's own tag
// `access` equals `true` — the canonical ABAC-privesc trust
// shape Iter 2 detects.
func trustDocTagConditional(t *testing.T, principal string) *PolicyDocument {
	t.Helper()
	raw := `{"Statement":[{
		"Effect": "Allow",
		"Action": "sts:AssumeRole",
		"Resource": "` + principal + `",
		"Condition": {"StringEquals": {"aws:ResourceTag/access": "true"}}
	}]}`
	doc := mustParse(t, raw)
	return &doc
}

// TestResolveChains_TagMutationPrivesc pins the load-bearing
// Iter 2 detection: a principal with iam:TagRole on a target
// role whose trust policy is conditioned on aws:ResourceTag/*
// can self-tag the role to satisfy the condition and assume
// it. The pre-Iter-2 walker only recognized sts:AssumeRole
// hops, so this primitive was completely invisible.
func TestResolveChains_TagMutationPrivesc(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	adminARN := "arn:aws:iam::123:role/admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					// CRITICAL: no sts:AssumeRole grant. The
					// only path to admin is via tag mutation.
					{Action: "iam:TagRole", Resource: adminARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			adminARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "*", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			adminARN: trustDocTagConditional(t, devARN),
		},
	}

	chains := ResolveChains(input)
	if len(chains) == 0 {
		t.Fatal("expected at least one chain (tag-mutation hop)")
	}

	// Find the tag-mutation hop. The classic walker won't have
	// produced anything (no sts:AssumeRole grant); only the
	// Iter 2 walker contributes.
	var tagHop *RoleHop
	for i := range chains {
		for j := range chains[i].Hops {
			if chains[i].Hops[j].Type == HopTypeTagMutation {
				tagHop = &chains[i].Hops[j]
				break
			}
		}
		if tagHop != nil {
			break
		}
	}
	if tagHop == nil {
		t.Fatalf("expected a tag_mutation hop; got chains: %+v", chains)
	}
	if tagHop.FromARN != devARN || tagHop.ToARN != adminARN {
		t.Errorf("hop endpoints: want %s → %s, got %s → %s",
			devARN, adminARN, tagHop.FromARN, tagHop.ToARN)
	}
	if tagHop.IsCrossAccount {
		t.Errorf("same-account hop must not be CrossAccount: %+v", tagHop)
	}

	// The chain reaches admin permissions (the post-tag-and-
	// assume access).
	if !HasTransitiveAdmin(chains) {
		t.Errorf("expected transitive admin via tag-mutation chain; chains: %+v", chains)
	}
}

// TestResolveChains_TagMutation_NoTrustCondition_NoEdge: the
// principal has iam:TagRole but the target's trust policy has
// NO tag condition. Tagging the role doesn't satisfy any
// trust requirement, so no privesc edge exists. This is the
// false-positive guard.
func TestResolveChains_TagMutation_NoTrustCondition_NoEdge(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	adminARN := "arn:aws:iam::123:role/admin"
	otherARN := "arn:aws:iam::123:role/other"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "iam:TagRole", Resource: adminARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			adminARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			// Trust policy has NO tag condition — only allows
			// some other principal directly.
			adminARN: trustDoc(t, otherARN),
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeTagMutation {
				t.Fatalf("must NOT emit tag_mutation hop when trust policy has no tag condition: %+v", chains)
			}
		}
	}
}

// TestResolveChains_TagMutation_NoTaggingPermission_NoEdge:
// principal has direct sts:AssumeRole and the target's trust
// policy is tag-conditional, but the principal has NO
// iam:TagRole. The trust condition will never be satisfied
// by the principal's actions. The tag-mutation walker must
// not invent a permission the principal doesn't have.
func TestResolveChains_TagMutation_NoTaggingPermission_NoEdge(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	adminARN := "arn:aws:iam::123:role/admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					// Has direct AssumeRole but NOT TagRole.
					{Action: "sts:AssumeRole", Resource: adminARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			adminARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			adminARN: trustDocTagConditional(t, devARN),
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeTagMutation {
				t.Fatalf("must NOT emit tag_mutation without iam:Tag* permission: %+v", chains)
			}
		}
	}
}

// TestResolveChains_TagMutation_WildcardAllUsers verifies the
// helper: iam:* and * also count as tagging permissions
// (super-broad grants implicitly include the tag-mutation
// primitive).
func TestResolveChains_TagMutation_WildcardCovered(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	adminARN := "arn:aws:iam::123:role/admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "iam:*", Resource: adminARN},
				},
				PrivilegeLevel: PrivilegeLevelStandard,
			},
			adminARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			adminARN: trustDocTagConditional(t, devARN),
		},
	}

	chains := ResolveChains(input)
	found := false
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeTagMutation && hop.ToARN == adminARN {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("iam:* should cover tag-mutation actions; chains: %+v", chains)
	}
}

// TestResolveChains_AssumeAndTagMutationCoexist: when both
// primitives apply (principal has BOTH sts:AssumeRole AND
// iam:TagRole on a tag-conditional trust target), both edges
// surface. This lets the explainer enumerate every available
// privesc primitive, not just the first one the walker found.
func TestResolveChains_AssumeAndTagMutationCoexist(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	adminARN := "arn:aws:iam::123:role/admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: adminARN},
					{Action: "iam:TagRole", Resource: adminARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			adminARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "*", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			adminARN: trustDocTagConditional(t, devARN),
		},
	}

	chains := ResolveChains(input)
	hasAssume := false
	hasTagMutation := false
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeAssume {
				hasAssume = true
			}
			if hop.Type == HopTypeTagMutation {
				hasTagMutation = true
			}
		}
	}
	if !hasAssume {
		t.Errorf("classic assume_role hop missing")
	}
	if !hasTagMutation {
		t.Errorf("tag_mutation hop missing")
	}
}

// trustDocService produces a trust policy that allows the named
// AWS service principal to assume the role via sts:AssumeRole.
// Built using real AWS Principal JSON shape so ExtractServiceTrusts
// (which probes the raw bytes) recognises it.
func trustDocServiceRaw(servicePrincipal string) string {
	return `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": "` + servicePrincipal + `"},
			"Action": "sts:AssumeRole"
		}]
	}`
}

// TestResolveChains_LambdaExecutionRolePrivesc pins the
// load-bearing Iter 3 detection: principal P with iam:PassRole
// on R AND lambda:InvokeFunction on any function reaches R's
// permissions by attaching R as a Lambda execution role and
// invoking the function.
func TestResolveChains_LambdaExecutionRolePrivesc(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	execARN := "arn:aws:iam::123:role/lambda-admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					// CRITICAL: NO sts:AssumeRole grant. The
					// only path to admin is via Lambda exec.
					{Action: "iam:PassRole", Resource: execARN},
					{Action: "lambda:InvokeFunction", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			execARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "*", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		ServiceTrusts: map[string][]string{
			execARN: {"lambda.amazonaws.com"},
		},
	}

	chains := ResolveChains(input)
	if len(chains) == 0 {
		t.Fatal("expected at least one chain (lambda_exec hop)")
	}

	var lambdaHop *RoleHop
	for i := range chains {
		for j := range chains[i].Hops {
			if chains[i].Hops[j].Type == HopTypeLambdaExec {
				lambdaHop = &chains[i].Hops[j]
			}
		}
	}
	if lambdaHop == nil {
		t.Fatalf("expected lambda_exec hop; got chains: %+v", chains)
	}
	if lambdaHop.FromARN != devARN || lambdaHop.ToARN != execARN {
		t.Errorf("hop endpoints: want %s → %s, got %s → %s",
			devARN, execARN, lambdaHop.FromARN, lambdaHop.ToARN)
	}
	if !HasTransitiveAdmin(chains) {
		t.Errorf("expected transitive admin via lambda_exec; chains: %+v", chains)
	}
}

// TestResolveChains_LambdaExec_NoServiceTrust_NoEdge: PassRole +
// InvokeFunction present, but the role's trust policy does NOT
// allow lambda.amazonaws.com → the service can't assume the role
// even if the principal tried to attach it. False-positive guard.
func TestResolveChains_LambdaExec_NoServiceTrust_NoEdge(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	execARN := "arn:aws:iam::123:role/wannabe-exec"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "iam:PassRole", Resource: execARN},
					{Action: "lambda:InvokeFunction", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			execARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		// ServiceTrusts deliberately empty: role's trust policy
		// doesn't allow lambda.amazonaws.com.
		ServiceTrusts: map[string][]string{},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeLambdaExec {
				t.Fatalf("must NOT emit lambda_exec without service trust: %+v", chains)
			}
		}
	}
}

// TestResolveChains_LambdaExec_NoPassRole_NoEdge: principal can
// invoke Lambda but cannot pass any role → service-exec primitive
// is incomplete.
func TestResolveChains_LambdaExec_NoPassRole_NoEdge(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	execARN := "arn:aws:iam::123:role/exec"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "lambda:InvokeFunction", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			execARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		ServiceTrusts: map[string][]string{
			execARN: {"lambda.amazonaws.com"},
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeLambdaExec {
				t.Fatalf("must NOT emit lambda_exec without iam:PassRole: %+v", chains)
			}
		}
	}
}

// TestResolveChains_FederatedAssumeRole exercises Iter 3's
// extension of the assume-action set to cover
// AssumeRoleWithWebIdentity (Cognito identity pools, federated
// OIDC) and AssumeRoleWithSAML.
func TestResolveChains_FederatedAssumeRole(t *testing.T) {
	cognitoARN := "arn:aws:iam::123:role/CognitoAuth"
	targetARN := "arn:aws:iam::123:role/admin"

	input := RoleChainInput{
		PrincipalARN: cognitoARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			cognitoARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRoleWithWebIdentity", Resource: targetARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			targetARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "*", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			targetARN: trustDoc(t, cognitoARN),
		},
	}

	chains := ResolveChains(input)
	if !HasTransitiveAdmin(chains) {
		t.Fatalf("AssumeRoleWithWebIdentity must produce a chain; got %+v", chains)
	}
}

// TestResolveChains_CFNExecRolePrivesc: CloudFormation execution
// role version of the same primitive. Pins the multi-service
// generality of the design.
func TestResolveChains_CFNExecRolePrivesc(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	cfnExecARN := "arn:aws:iam::123:role/cfn-admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "iam:PassRole", Resource: cfnExecARN},
					{Action: "cloudformation:CreateStack", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			cfnExecARN: {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		ServiceTrusts: map[string][]string{
			cfnExecARN: {"cloudformation.amazonaws.com"},
		},
	}

	chains := ResolveChains(input)
	found := false
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeCfnExec && hop.ToARN == cfnExecARN {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected cfn_exec hop; got %+v", chains)
	}
}

// TestResolveChains_ServiceExec_WildcardPassRoleSkipped: a
// wildcard PassRole grant is itself a posture concern (caught by
// CTL.IAM.POLICY.* controls); the chain walker conservatively
// skips it rather than enumerating every role in the snapshot.
// This is the v1 deferral documented in resolveServiceExecChains.
func TestResolveChains_ServiceExec_WildcardPassRoleSkipped(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	execARN := "arn:aws:iam::123:role/exec"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "iam:PassRole", Resource: "*"},
					{Action: "lambda:InvokeFunction", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			execARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		ServiceTrusts: map[string][]string{
			execARN: {"lambda.amazonaws.com"},
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeLambdaExec {
				t.Fatalf("wildcard PassRole must not enumerate target roles: %+v", chains)
			}
		}
	}
}

// TestExtractServiceTrusts_ServicePrincipalShapes pins the raw-
// JSON probe: a real AWS trust policy with Principal: {Service: ...}
// must yield the expected service-principal list, even though the
// existing iam.Statement parser drops the Principal field.
func TestExtractServiceTrusts_ServicePrincipalShapes(t *testing.T) {
	cases := []struct {
		name string
		json string
		want []string
	}{
		{
			name: "single string service",
			json: trustDocServiceRaw("lambda.amazonaws.com"),
			want: []string{"lambda.amazonaws.com"},
		},
		{
			name: "list of services",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRole",
					"Principal": {"Service": ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]}
				}]
			}`,
			want: []string{"lambda.amazonaws.com", "ecs-tasks.amazonaws.com"},
		},
		{
			name: "non-AssumeRole action skipped",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Principal": {"Service": "lambda.amazonaws.com"}
				}]
			}`,
			want: nil,
		},
		{
			name: "Deny statement skipped",
			json: `{
				"Statement": [{
					"Effect": "Deny",
					"Action": "sts:AssumeRole",
					"Principal": {"Service": "lambda.amazonaws.com"}
				}]
			}`,
			want: nil,
		},
		{
			name: "no service principal",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRole",
					"Principal": {"AWS": "arn:aws:iam::123:role/dev"}
				}]
			}`,
			want: nil,
		},
		{
			name: "federated assume action",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRoleWithWebIdentity",
					"Principal": {"Service": "cognito-identity.amazonaws.com"}
				}]
			}`,
			want: []string{"cognito-identity.amazonaws.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseServicePrincipalsAllowingAssume(tc.json)
			if len(got) != len(tc.want) {
				t.Fatalf("len: want %d (%v), got %d (%v)", len(tc.want), tc.want, len(got), got)
			}
			gotSet := map[string]struct{}{}
			for _, g := range got {
				gotSet[strings.ToLower(g)] = struct{}{}
			}
			for _, w := range tc.want {
				if _, ok := gotSet[strings.ToLower(w)]; !ok {
					t.Errorf("missing %q in result %v", w, got)
				}
			}
		})
	}
}
