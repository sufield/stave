package iam

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
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

// trustDocAccountRootRaw produces a trust policy JSON string that
// admits every principal in the named account via
// `Principal: AWS: arn:aws:iam::<acct>:root`. Built using the
// real-world AWS shape so ExtractAWSTrustedPrincipals (which
// probes the raw bytes) recognises it. This is the load-bearing
// test fixture for Iter 4: the iam.Statement parser drops the
// Principal field, so a role using this trust pattern is invisible
// to the legacy walker without the side-channel.
func trustDocAccountRootRaw(account string) string {
	return `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::` + account + `:root"},
			"Action": "sts:AssumeRole"
		}]
	}`
}

// TestResolveChains_AccountRootTrustExpansion pins the load-
// bearing Iter 4 detection: a principal in account 222 reaches
// a role in account 111 whose trust policy account-root-trusts
// 222, even though the role's trust policy lists no specific
// ARN. This is the cross-account compromise propagation
// described in gap-prompt.md:16.
func TestResolveChains_AccountRootTrustExpansion(t *testing.T) {
	devARN := "arn:aws:iam::222222222222:role/dev"
	crossARN := "arn:aws:iam::111111111111:role/cross-admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "222222222222",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: crossARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			crossARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "*", Resource: "*"},
				},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		// AWSPrincipalTrusts is the side-channel: the role in
		// account 111 trusts every principal in account 222 via
		// :root expansion. No PolicyDocument-level trust is
		// staged — this asserts the side-channel works on its
		// own, which is the realistic shape of any production
		// trust policy that uses `Principal: AWS: ...`.
		AWSPrincipalTrusts: map[string]AWSTrustedPrincipals{
			crossARN: {AccountRoots: []string{"222222222222"}},
		},
	}

	chains := ResolveChains(input)
	if !HasTransitiveAdmin(chains) {
		t.Fatalf("expected admin chain via account-root trust; got %+v", chains)
	}
	// Crossing accounts: the hop must be flagged so consumers can
	// distinguish same-account assumption from cross-account.
	found := false
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.ToARN == crossARN && hop.IsCrossAccount {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected cross-account flag on the account-root hop")
	}
}

// TestResolveChains_AccountRootTrustRejectsForeignAccount: the
// negative case. A principal in account 333 must NOT reach a role
// whose trust policy account-root-trusts only 222.
func TestResolveChains_AccountRootTrustRejectsForeignAccount(t *testing.T) {
	foreignARN := "arn:aws:iam::333333333333:role/dev"
	crossARN := "arn:aws:iam::111111111111:role/cross-admin"

	input := RoleChainInput{
		PrincipalARN: foreignARN,
		AccountID:    "333333333333",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			foreignARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: crossARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			crossARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		AWSPrincipalTrusts: map[string]AWSTrustedPrincipals{
			crossARN: {AccountRoots: []string{"222222222222"}},
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		if ch.FinalRoleARN == crossARN && ch.TerminationReason == ChainTerminatedNormal {
			t.Fatalf("foreign-account principal must NOT reach role: %+v", chains)
		}
	}
}

// TestResolveChains_ExactARNTrustViaAWSPrincipal exercises the
// other half of the side-channel: when the trust policy admits
// a SPECIFIC ARN via `Principal: AWS: arn:...:role/dev`, only
// that exact principal is allowed. Verifies Iter 4's exact-ARN
// path doesn't accidentally inherit the account-root expansion.
func TestResolveChains_ExactARNTrustViaAWSPrincipal(t *testing.T) {
	devARN := "arn:aws:iam::222222222222:role/dev"
	otherARN := "arn:aws:iam::222222222222:role/other"
	crossARN := "arn:aws:iam::111111111111:role/cross-admin"

	commonResolved := buildResolvedIndex(map[string]ResolvedPermissions{
		devARN: {
			EffectiveAllow: []ActionGrant{{Action: "sts:AssumeRole", Resource: crossARN}},
			PrivilegeLevel: PrivilegeLevelLimited,
		},
		otherARN: {
			EffectiveAllow: []ActionGrant{{Action: "sts:AssumeRole", Resource: crossARN}},
			PrivilegeLevel: PrivilegeLevelLimited,
		},
		crossARN: {
			EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
			PrivilegeLevel: PrivilegeLevelAdmin,
		},
	})
	awsTrust := map[string]AWSTrustedPrincipals{
		crossARN: {ExactARNs: []string{devARN}},
	}

	// dev (admitted) reaches cross-admin.
	devChains := ResolveChains(RoleChainInput{
		PrincipalARN:       devARN,
		AccountID:          "222222222222",
		ResolvedIndex:      commonResolved,
		AWSPrincipalTrusts: awsTrust,
	})
	if !HasTransitiveAdmin(devChains) {
		t.Fatalf("dev must reach admin via exact-ARN trust; got %+v", devChains)
	}

	// other (NOT admitted, even in same account) does not reach.
	otherChains := ResolveChains(RoleChainInput{
		PrincipalARN:       otherARN,
		AccountID:          "222222222222",
		ResolvedIndex:      commonResolved,
		AWSPrincipalTrusts: awsTrust,
	})
	if HasTransitiveAdmin(otherChains) {
		t.Fatalf("non-listed ARN must NOT inherit access; got %+v", otherChains)
	}
}

// TestExtractAWSTrustedPrincipals_ParsesAccountRootShapes pins
// the raw-JSON probe: every wire shape AWS accepts for the
// account-root pattern produces the same canonical AccountRoots
// entry. The bare-account-number form, the :root ARN form, and
// the list-of-roots form must all classify correctly.
func TestExtractAWSTrustedPrincipals_ParsesAccountRootShapes(t *testing.T) {
	cases := []struct {
		name         string
		json         string
		wantRoots    []string
		wantExacts   []string
		wantWildcard bool
	}{
		{
			name:      "single root ARN",
			json:      trustDocAccountRootRaw("222222222222"),
			wantRoots: []string{"222222222222"},
		},
		{
			name: "bare account number",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRole",
					"Principal": {"AWS": "222222222222"}
				}]
			}`,
			wantRoots: []string{"222222222222"},
		},
		{
			name: "list of roots",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRole",
					"Principal": {"AWS": [
						"arn:aws:iam::111111111111:root",
						"arn:aws:iam::222222222222:root"
					]}
				}]
			}`,
			wantRoots: []string{"111111111111", "222222222222"},
		},
		{
			name: "exact ARN preserved",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRole",
					"Principal": {"AWS": "arn:aws:iam::222222222222:role/dev"}
				}]
			}`,
			wantExacts: []string{"arn:aws:iam::222222222222:role/dev"},
		},
		{
			name: "Deny ignored",
			json: `{
				"Statement": [{
					"Effect": "Deny",
					"Action": "sts:AssumeRole",
					"Principal": {"AWS": "arn:aws:iam::222222222222:root"}
				}]
			}`,
			// nothing — Deny statements don't grant trust.
		},
		{
			name: "non-AssumeRole action ignored",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Principal": {"AWS": "arn:aws:iam::222222222222:root"}
				}]
			}`,
		},
		{
			name: "federated assume action accepted",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRoleWithSAML",
					"Principal": {"AWS": "arn:aws:iam::222222222222:root"}
				}]
			}`,
			wantRoots: []string{"222222222222"},
		},
		{
			name: "bare wildcard string",
			json: `{
				"Statement": [{
					"Effect": "Allow",
					"Action": "sts:AssumeRole",
					"Principal": "*"
				}]
			}`,
			wantWildcard: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAWSPrincipalsAllowingAssume(tc.json)
			assertStringSliceEqual(t, "AccountRoots", got.AccountRoots, tc.wantRoots)
			assertStringSliceEqual(t, "ExactARNs", got.ExactARNs, tc.wantExacts)
			if got.Wildcard != tc.wantWildcard {
				t.Errorf("Wildcard: want %v, got %v", tc.wantWildcard, got.Wildcard)
			}
		})
	}
}

func assertStringSliceEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: want %v (len %d), got %v (len %d)",
			label, want, len(want), got, len(got))
		return
	}
	gotSet := map[string]struct{}{}
	for _, g := range got {
		gotSet[g] = struct{}{}
	}
	for _, w := range want {
		if _, ok := gotSet[w]; !ok {
			t.Errorf("%s: missing %q in %v", label, w, got)
		}
	}
}

// TestResolveChains_ScheduledDeletionAnnotation pins the load-
// bearing Iter 5 (TOCTOU) detection: a chain pointing at a role
// scheduled for future deletion gets stamped with the deletion
// timestamp so downstream solvers can surface the future-ghost
// reference. The chain remains reachable (the walker doesn't
// drop it) — only the annotation is added.
func TestResolveChains_ScheduledDeletionAnnotation(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	doomedARN := "arn:aws:iam::123:role/doomed-admin"
	deletionTime := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "sts:AssumeRole", Resource: doomedARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			doomedARN: {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			doomedARN: trustDoc(t, devARN),
		},
		ScheduledDeletions: map[string]time.Time{
			doomedARN: deletionTime,
		},
	}

	chains := ResolveChains(input)
	if len(chains) == 0 {
		t.Fatal("expected at least one chain reaching doomed admin")
	}
	found := false
	for _, ch := range chains {
		if ch.FinalRoleARN == doomedARN {
			if ch.ScheduledDeletionAt.IsZero() {
				t.Errorf("chain to doomed role missing ScheduledDeletionAt; got zero")
			}
			if !ch.ScheduledDeletionAt.Equal(deletionTime) {
				t.Errorf("ScheduledDeletionAt: want %s, got %s", deletionTime, ch.ScheduledDeletionAt)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no chain reached %s; got %+v", doomedARN, chains)
	}
}

// TestResolveChains_ScheduledDeletion_TakesEarliest: when a chain
// crosses MULTIPLE roles with scheduled deletions, the chain's
// ScheduledDeletionAt records the EARLIEST time — that is the
// horizon at which the chain first becomes stale. A later
// deletion in the chain is moot once the earlier one fires.
func TestResolveChains_ScheduledDeletion_TakesEarliest(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	midARN := "arn:aws:iam::123:role/mid"
	finalARN := "arn:aws:iam::123:role/final-admin"
	earlyDel := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	lateDel := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{{Action: "sts:AssumeRole", Resource: midARN}},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			midARN: {
				EffectiveAllow: []ActionGrant{{Action: "sts:AssumeRole", Resource: finalARN}},
				PrivilegeLevel: PrivilegeLevelStandard,
			},
			finalARN: {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			midARN:   trustDoc(t, devARN),
			finalARN: trustDoc(t, midARN),
		},
		ScheduledDeletions: map[string]time.Time{
			midARN:   lateDel,  // mid deleted later
			finalARN: earlyDel, // final deleted earlier
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		if ch.FinalRoleARN == finalARN && len(ch.Hops) >= 2 {
			if !ch.ScheduledDeletionAt.Equal(earlyDel) {
				t.Errorf("multi-deletion chain: want earliest %s, got %s",
					earlyDel, ch.ScheduledDeletionAt)
			}
			return
		}
	}
	t.Fatalf("expected multi-hop chain to %s; got %+v", finalARN, chains)
}

// TestResolveChains_NoScheduledDeletion_ZeroAnnotation: chains
// not crossing any scheduled-for-deletion role keep the
// annotation as zero-time. Negative case.
func TestResolveChains_NoScheduledDeletion_ZeroAnnotation(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	adminARN := "arn:aws:iam::123:role/admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{{Action: "sts:AssumeRole", Resource: adminARN}},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			adminARN: {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		TrustPolicies: map[string]*PolicyDocument{
			adminARN: trustDoc(t, devARN),
		},
		// ScheduledDeletions deliberately empty.
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		if !ch.ScheduledDeletionAt.IsZero() {
			t.Errorf("chain without scheduled deletion has non-zero annotation: %s",
				ch.ScheduledDeletionAt)
		}
	}
}

// TestExtractScheduledDeletions_ReadsCanonicalKeys verifies the
// extractor recognises both property-key conventions Stave's
// collectors use: identity.lifecycle.scheduled_for_deletion_at
// (canonical IAM) and identity.lifecycle.deletion_date (the
// secretsmanager-shaped fallback). Both must yield the same
// timestamp; malformed entries are silently dropped.
func TestExtractScheduledDeletions_ReadsCanonicalKeys(t *testing.T) {
	wantTime := time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		props map[string]any
		want  bool
	}{
		{
			name: "canonical scheduled_for_deletion_at",
			props: map[string]any{
				"identity": map[string]any{
					"lifecycle": map[string]any{
						"scheduled_for_deletion_at": "2027-01-15T12:00:00Z",
					},
				},
			},
			want: true,
		},
		{
			name: "fallback deletion_date",
			props: map[string]any{
				"identity": map[string]any{
					"lifecycle": map[string]any{
						"deletion_date": "2027-01-15T12:00:00Z",
					},
				},
			},
			want: true,
		},
		{
			name: "canonical wins over fallback",
			props: map[string]any{
				"identity": map[string]any{
					"lifecycle": map[string]any{
						"scheduled_for_deletion_at": "2027-01-15T12:00:00Z",
						"deletion_date":             "2099-12-31T23:59:59Z",
					},
				},
			},
			want: true,
		},
		{
			name: "malformed timestamp dropped",
			props: map[string]any{
				"identity": map[string]any{
					"lifecycle": map[string]any{
						"scheduled_for_deletion_at": "tomorrow",
					},
				},
			},
			want: false,
		},
		{
			name:  "no lifecycle key",
			props: map[string]any{"identity": map[string]any{}},
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := readDeletionTimestamp(tc.props)
			if tc.want && !got.Equal(wantTime) {
				t.Errorf("want %s, got %s", wantTime, got)
			}
			if !tc.want && !got.IsZero() {
				t.Errorf("expected zero time, got %s", got)
			}
		})
	}
}

// TestResolveChains_LambdaInvokeExisting_ConfusedDeputy pins the
// load-bearing Iter 6 detection: a principal P with
// `lambda:InvokeFunction` on a SPECIFIC existing function ARN
// reaches the role bound to that function, even though P has no
// iam:PassRole. This is the confused-deputy "use-existing"
// pattern from gap-prompt.md:10 — distinct from Iter 3's
// create-and-pass primitive.
func TestResolveChains_LambdaInvokeExisting_ConfusedDeputy(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	funcARN := "arn:aws:lambda:us-east-1:123:function:legacy-prod"
	adminARN := "arn:aws:iam::123:role/legacy-prod-exec"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					// CRITICAL: NO iam:PassRole anywhere. The
					// confused-deputy path requires only the
					// trigger action against the existing function
					// — its role binding is already in place.
					{Action: "lambda:InvokeFunction", Resource: funcARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			adminARN: {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		ResourceRoleBindings: map[string]ResourceRoleBinding{
			funcARN: {
				ResourceARN: funcARN,
				RoleARN:     adminARN,
				ServiceKind: "lambda",
			},
		},
	}

	chains := ResolveChains(input)
	if !HasTransitiveAdmin(chains) {
		t.Fatalf("expected admin chain via lambda_invoke_existing; got %+v", chains)
	}
	found := false
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeLambdaInvokeExisting && hop.ToARN == adminARN {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected lambda_invoke_existing hop; got %+v", chains)
	}
}

// TestResolveChains_InvokeExisting_WildcardResourceSkipped pins
// the v1 deferral: a wildcard `lambda:InvokeFunction *` grant
// must NOT enumerate every function in the snapshot. Wildcards
// are caught by the catalog's broad-permission controls; the
// confused-deputy walker stays focused on specific resource ARNs.
func TestResolveChains_InvokeExisting_WildcardResourceSkipped(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	funcARN := "arn:aws:lambda:us-east-1:123:function:legacy-prod"
	adminARN := "arn:aws:iam::123:role/legacy-prod-exec"

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
			adminARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		ResourceRoleBindings: map[string]ResourceRoleBinding{
			funcARN: {ResourceARN: funcARN, RoleARN: adminARN, ServiceKind: "lambda"},
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeLambdaInvokeExisting {
				t.Fatalf("wildcard resource must not enumerate bindings: %+v", chains)
			}
		}
	}
}

// TestResolveChains_InvokeExisting_NoBinding_NoEdge: principal
// has the trigger action on a specific ARN but the snapshot has
// no role binding recorded for that ARN. The walker cannot
// attribute privilege and must skip silently — no chain emitted.
func TestResolveChains_InvokeExisting_NoBinding_NoEdge(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	funcARN := "arn:aws:lambda:us-east-1:123:function:unknown"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "lambda:InvokeFunction", Resource: funcARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
		}),
		// ResourceRoleBindings deliberately empty.
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeLambdaInvokeExisting {
				t.Fatalf("must NOT emit hop without binding: %+v", chains)
			}
		}
	}
}

// TestResolveChains_CFNUpdateExisting exercises the second v1
// service: cloudformation:UpdateStack on an existing stack with
// a pre-bound execution role. The same primitive shape as
// Lambda invoke; pins multi-service generality.
func TestResolveChains_CFNUpdateExisting(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	stackARN := "arn:aws:cloudformation:us-east-1:123:stack/legacy/abc"
	cfnRoleARN := "arn:aws:iam::123:role/legacy-cfn-exec"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					{Action: "cloudformation:UpdateStack", Resource: stackARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			cfnRoleARN: {
				EffectiveAllow: []ActionGrant{{Action: "*", Resource: "*"}},
				PrivilegeLevel: PrivilegeLevelAdmin,
			},
		}),
		ResourceRoleBindings: map[string]ResourceRoleBinding{
			stackARN: {
				ResourceARN: stackARN,
				RoleARN:     cfnRoleARN,
				ServiceKind: "cloudformation",
			},
		},
	}

	chains := ResolveChains(input)
	found := false
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeCfnUpdateExisting && hop.ToARN == cfnRoleARN {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected cfn_update_existing hop; got %+v", chains)
	}
}

// TestResolveChains_InvokeExisting_ServiceKindMismatch: a
// resource-role binding whose ServiceKind doesn't match the
// trigger action's service must be ignored. Defends against
// extractor bugs that classify bindings incorrectly.
func TestResolveChains_InvokeExisting_ServiceKindMismatch(t *testing.T) {
	devARN := "arn:aws:iam::123:role/dev"
	stackARN := "arn:aws:cloudformation:us-east-1:123:stack/x/y"
	roleARN := "arn:aws:iam::123:role/admin"

	input := RoleChainInput{
		PrincipalARN: devARN,
		AccountID:    "123",
		ResolvedIndex: buildResolvedIndex(map[string]ResolvedPermissions{
			devARN: {
				EffectiveAllow: []ActionGrant{
					// Lambda action against a CFN-typed binding —
					// nonsense pairing, must NOT fire.
					{Action: "lambda:InvokeFunction", Resource: stackARN},
				},
				PrivilegeLevel: PrivilegeLevelLimited,
			},
			roleARN: {PrivilegeLevel: PrivilegeLevelAdmin},
		}),
		ResourceRoleBindings: map[string]ResourceRoleBinding{
			stackARN: {ResourceARN: stackARN, RoleARN: roleARN, ServiceKind: "cloudformation"},
		},
	}

	chains := ResolveChains(input)
	for _, ch := range chains {
		for _, hop := range ch.Hops {
			if hop.Type == HopTypeLambdaInvokeExisting {
				t.Fatalf("service-kind mismatch must skip: %+v", chains)
			}
		}
	}
}

// TestExtractResourceRoleBindings_LambdaAndCFN exercises the
// extractor against the v1 supported asset types. The Lambda
// function reads from properties.compute.role_arn; the CFN stack
// from properties.cloudformation.role_arn. Unrelated asset types
// are silently ignored.
func TestExtractResourceRoleBindings_LambdaAndCFN(t *testing.T) {
	// Mock-style helper to build a snapshot inline. Using a
	// snapshotForBindings helper to avoid pulling in the full
	// snapshot factory; the function under test only touches
	// snap.Assets[*].{Type, ID, Properties}.
	snap := snapshotWithAssets(t, []bindingFixture{
		{
			ID:   "arn:aws:lambda:us-east-1:111:function:legacy",
			Type: "aws_lambda_function",
			Props: map[string]any{
				"compute": map[string]any{
					"role_arn": "arn:aws:iam::111:role/lambda-exec",
				},
			},
		},
		{
			ID:   "arn:aws:cloudformation:us-east-1:111:stack/legacy/abc",
			Type: "aws_cloudformation_stack",
			Props: map[string]any{
				"cloudformation": map[string]any{
					"role_arn": "arn:aws:iam::111:role/cfn-exec",
				},
			},
		},
		{
			ID:   "arn:aws:s3:::ignored-bucket",
			Type: "aws_s3_bucket",
			Props: map[string]any{},
		},
		{
			ID:   "arn:aws:lambda:us-east-1:111:function:no-role",
			Type: "aws_lambda_function",
			Props: map[string]any{
				"compute": map[string]any{
					// No role_arn key — should be skipped.
				},
			},
		},
	})

	got := ExtractResourceRoleBindings(snap)
	if len(got) != 2 {
		t.Fatalf("want 2 bindings, got %d: %+v", len(got), got)
	}
	lambdaARN := "arn:aws:lambda:us-east-1:111:function:legacy"
	if b, ok := got[lambdaARN]; !ok {
		t.Errorf("missing Lambda binding")
	} else {
		if b.RoleARN != "arn:aws:iam::111:role/lambda-exec" {
			t.Errorf("Lambda role: got %q", b.RoleARN)
		}
		if b.ServiceKind != "lambda" {
			t.Errorf("Lambda kind: got %q", b.ServiceKind)
		}
	}
	cfnARN := "arn:aws:cloudformation:us-east-1:111:stack/legacy/abc"
	if b, ok := got[cfnARN]; !ok {
		t.Errorf("missing CFN binding")
	} else {
		if b.ServiceKind != "cloudformation" {
			t.Errorf("CFN kind: got %q", b.ServiceKind)
		}
	}
}

// bindingFixture describes a single asset to inject into a
// snapshot for the resource-binding extractor tests.
type bindingFixture struct {
	ID    string
	Type  string
	Props map[string]any
}

// snapshotWithAssets builds an asset.Snapshot containing exactly
// the supplied fixtures. Inline rather than reaching for a
// full-fledged snapshot builder because the extractor only
// touches Assets[*].{ID, Type, Properties}.
func snapshotWithAssets(t *testing.T, fixtures []bindingFixture) *asset.Snapshot {
	t.Helper()
	snap := &asset.Snapshot{}
	for _, f := range fixtures {
		snap.Assets = append(snap.Assets, asset.Asset{
			ID:         asset.ID(f.ID),
			Type:       kernel.AssetType(f.Type),
			Properties: f.Props,
		})
	}
	return snap
}
