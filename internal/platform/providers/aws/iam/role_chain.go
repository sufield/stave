package iam

import (
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/util/sets"
	"github.com/sufield/stave/internal/util/strutil"
)

// MaxChainDepth is the maximum number of role assumption hops before
// the resolver terminates the chain.
const MaxChainDepth = 5

// MaxChainsPerPrincipal caps the total chains to prevent blowup on
// principals with very broad sts:AssumeRole grants.
const MaxChainsPerPrincipal = 100

// ChainTerminationReason indicates why a chain stopped being resolved.
type ChainTerminationReason int

const (
	ChainTerminatedNormal        ChainTerminationReason = iota
	ChainTerminatedMaxDepth                             // hit 5-hop limit
	ChainTerminatedCycle                                // detected cycle
	ChainTerminatedNotInSnapshot                        // role not in snapshot
)

// HopType classifies how a principal reaches a role in a single hop.
type HopType string

// Hop kinds.
//
// Iter 2 introduced HopTypeTagMutation for the ABAC privilege-
// escalation primitive (iam:TagRole on a tag-conditional-trust role).
//
// Iter 3 adds per-service execution-role hops for the
// iam:PassRole + service-trigger primitive: principal with
// PassRole on role R AND a service-trigger action gains R's
// permissions by invoking the service. R's trust policy must
// allow the matching service principal. Iter 3 also extends
// HopTypeAssume to cover sts:AssumeRoleWithWebIdentity and
// sts:AssumeRoleWithSAML (federated identities, Cognito, OIDC,
// SAML), inline in the recursive walker rather than as new
// hop kinds — the assume primitive is the same; only the
// action verb changes.
const (
	HopTypeAssume        HopType = "assume_role"
	HopTypeTagMutation   HopType = "tag_mutation"
	HopTypeLambdaExec    HopType = "lambda_exec"
	HopTypeEcsExec       HopType = "ecs_exec"
	HopTypeCodebuildExec HopType = "codebuild_exec"
	HopTypeGlueExec      HopType = "glue_exec"
	HopTypeCfnExec       HopType = "cfn_exec"

	// Iter 6 (confused deputy): the *invoke-existing* primitive.
	// Distinct from Iter 3's *create-and-pass*: the binding is
	// already in place before the attack, so iam:PassRole is NOT a
	// prerequisite. The principal needs only the trigger action on
	// a SPECIFIC resource ARN that the snapshot reports as already
	// bound to the target role.
	HopTypeLambdaInvokeExisting HopType = "lambda_invoke_existing"
	HopTypeCfnUpdateExisting    HopType = "cfn_update_existing"
)

// RoleHop is one step in a transitive role assumption chain.
//
// Type defaults to HopTypeAssume when zero-valued so existing
// callers that constructed RoleHop literals before Iter 2 produce
// the same wire-shape under the new field.
type RoleHop struct {
	FromARN        string
	ToARN          string
	IsCrossAccount bool
	Type           HopType
}

// RoleChain represents a transitive path from a principal to a final
// role via one or more hops. Iter 2: hops may now be tag-mutation
// edges in addition to sts:AssumeRole edges.
type RoleChain struct {
	Hops              []RoleHop
	FinalRoleARN      string
	TransitiveLevel   PrivilegeLevel
	TerminationReason ChainTerminationReason

	// ScheduledDeletionAt records the EARLIEST scheduled-deletion
	// timestamp encountered across this chain's hops. Zero value
	// means no hop along the chain references a role that is
	// scheduled for deletion.
	//
	// Iter 5 (TOCTOU): a chain reaching a role that will be deleted
	// at time T is reachable now but unsafe at T+1; any consumer
	// caching the reachability decision risks a stale grant. The
	// solver / explainer uses this annotation to surface the
	// future-ghost-reference pattern alongside the current
	// chain — it does NOT drop the chain (the chain is still
	// reachable today), it adds a future-deadline warning.
	ScheduledDeletionAt time.Time
}

// RoleChainInput provides the data needed for chain resolution.
type RoleChainInput struct {
	// PrincipalARN is the starting principal.
	PrincipalARN string

	// ResolvedIndex maps principal/role ARN → ResolvedPermissions
	// (from Iteration 1 resolution of all principals).
	ResolvedIndex map[string]*ResolvedPermissions

	// TrustPolicies maps role ARN → trust policy document.
	TrustPolicies map[string]*PolicyDocument

	// ServiceTrusts maps role ARN → list of service principals the
	// role's trust policy allows for sts:AssumeRole. Populated by
	// ExtractServiceTrusts during snapshot ingestion. The recursive
	// chain walker uses TrustPolicies for ARN-principal trust
	// reciprocity; the Iter 3 service-execution walker uses
	// ServiceTrusts for service-principal trust reciprocity. Empty
	// or nil ServiceTrusts disables service-execution-hop emission
	// without disabling the rest of the walker.
	ServiceTrusts map[string][]string

	// AWSPrincipalTrusts maps role ARN → AWSTrustedPrincipals (the
	// account-roots / exact-ARNs / wildcard surface extracted from
	// raw trust JSON). Populated by ExtractAWSTrustedPrincipals.
	// trustPolicyAllows consults this side-channel in addition to
	// TrustPolicies because the iam.Statement parser drops the
	// Principal field; without this map, real-world account-root
	// trust patterns (`Principal: AWS: arn:aws:iam::<acct>:root`)
	// are invisible to the walker. Iter 4: closes the trust-
	// transitivity gap so a compromised principal in account B is
	// recognised as an assumer of any role whose trust policy
	// account-root-trusts B.
	AWSPrincipalTrusts map[string]AWSTrustedPrincipals

	// ScheduledDeletions maps principal/role ARN → the timestamp at
	// which the identity is scheduled to be deleted. Populated by
	// ExtractScheduledDeletions. The walker reads this map to
	// annotate emitted chains with the EARLIEST deletion timestamp
	// encountered along their hops — a chain reaching a
	// scheduled-for-deletion role is reachable today but stale
	// after T (the TOCTOU "future ghost reference" pattern). Empty
	// or nil disables the annotation without affecting which chains
	// the walker emits.
	ScheduledDeletions map[string]time.Time

	// ResourceRoleBindings maps service-resource ARN (Lambda
	// function, CFN stack, ...) → the IAM role attached to that
	// resource. Populated by ExtractResourceRoleBindings. Iter 6
	// (confused deputy): the invoke-existing walker reads this map
	// to detect "principal P has trigger action T on resource R,
	// R is already bound to admin role Q" — an indirect privesc
	// path that requires no iam:PassRole because the binding
	// pre-existed the attack. Empty or nil disables the walker
	// without affecting other primitives.
	ResourceRoleBindings map[string]ResourceRoleBinding

	// AccountID of the starting principal, for cross-account detection.
	AccountID string
}

// ResolveChains computes all transitive role-reachability paths
// from the starting principal. Each chain is a sequence of hops
// ending at a role whose resolved permissions represent the
// transitive access gained through that path.
//
// Iter 3 dispatches three orthogonal walkers:
//   - resolveChainRecursive: classic sts:AssumeRole hops plus
//     federated assume actions (depth-bounded, cycle-aware).
//   - resolveTagMutationChains (Iter 2): ABAC privesc edges where
//     the principal can self-tag the target role to satisfy a
//     tag-conditional trust policy.
//   - resolveServiceExecChains (Iter 3): the iam:PassRole +
//     service-trigger primitive across Lambda / ECS / CFN /
//     CodeBuild / Glue. Single-hop edges; multi-hop transitivity
//     is the assume walker's job.
//
// Concatenated results: a principal that reaches a role via
// MULTIPLE primitives surfaces each edge separately so the
// downstream solver / explainer can name every available privesc
// path, not just the first one the walker found.
func ResolveChains(input RoleChainInput) []RoleChain {
	visited := sets.New[string]()
	var chains []RoleChain
	resolveChainRecursive(input, input.PrincipalARN, visited, 0, nil, &chains)
	chains = append(chains, resolveTagMutationChains(input)...)
	chains = append(chains, resolveServiceExecChains(input)...)
	chains = append(chains, resolveExistingResourceInvocations(input)...)
	annotateScheduledDeletions(chains, input.ScheduledDeletions)
	return chains
}

// annotateScheduledDeletions stamps each chain with the earliest
// scheduled-deletion timestamp encountered across its hops. Run
// once at ResolveChains exit so each emission site stays focused
// on chain construction. Iter 5: chains traversing a role
// scheduled for future deletion get a ScheduledDeletionAt marker
// so downstream consumers can surface the TOCTOU pattern without
// re-walking the chain.
func annotateScheduledDeletions(chains []RoleChain, deletions map[string]time.Time) {
	if len(deletions) == 0 || len(chains) == 0 {
		return
	}
	for i := range chains {
		earliest := time.Time{}
		// Check the starting principal too — if the assumer itself
		// is scheduled for deletion, every chain it produces is
		// stale on the same horizon.
		if len(chains[i].Hops) > 0 {
			if t, ok := lookupDeletion(deletions, chains[i].Hops[0].FromARN); ok {
				earliest = t
			}
		}
		for _, hop := range chains[i].Hops {
			t, ok := lookupDeletion(deletions, hop.ToARN)
			if !ok {
				continue
			}
			if earliest.IsZero() || t.Before(earliest) {
				earliest = t
			}
		}
		if !earliest.IsZero() {
			chains[i].ScheduledDeletionAt = earliest
		}
	}
}

// serviceExec describes one (action-set → service-principal → hop-kind)
// triple for the service-execution walker. The principal must
// have iam:PassRole on the target role AND any one of the trigger
// actions; the role's trust policy must allow ServicePrincipal.
type serviceExec struct {
	HopType          HopType
	ServicePrincipal string
	TriggerActions   []string
}

// serviceExecPrimitives lists the AWS services Stave models for
// service-execution hops in v1. Each entry pairs:
//   - A canonical AWS service principal (e.g. "lambda.amazonaws.com")
//   - The set of caller-side actions that "drive" the service to
//     assume an attached execution/task role on the caller's
//     behalf
//   - The HopType the SIR labels the resulting edge with
//
// Adding a new service is a single-edit extension to this list.
// Future iterations may broaden the trigger-action set (e.g.,
// additional Lambda update verbs) — kept narrow today to avoid
// false positives from read-only management actions.
var serviceExecPrimitives = []serviceExec{
	{
		HopType:          HopTypeLambdaExec,
		ServicePrincipal: "lambda.amazonaws.com",
		TriggerActions: []string{
			"lambda:InvokeFunction",
			"lambda:CreateFunction",
			"lambda:UpdateFunctionConfiguration",
			"lambda:UpdateFunctionCode",
		},
	},
	{
		HopType:          HopTypeEcsExec,
		ServicePrincipal: "ecs-tasks.amazonaws.com",
		TriggerActions: []string{
			"ecs:RunTask",
			"ecs:StartTask",
			"ecs:RegisterTaskDefinition",
		},
	},
	{
		HopType:          HopTypeCodebuildExec,
		ServicePrincipal: "codebuild.amazonaws.com",
		TriggerActions: []string{
			"codebuild:StartBuild",
			"codebuild:CreateProject",
			"codebuild:UpdateProject",
		},
	},
	{
		HopType:          HopTypeGlueExec,
		ServicePrincipal: "glue.amazonaws.com",
		TriggerActions: []string{
			"glue:CreateJob",
			"glue:StartJobRun",
			"glue:UpdateJob",
		},
	},
	{
		HopType:          HopTypeCfnExec,
		ServicePrincipal: "cloudformation.amazonaws.com",
		TriggerActions: []string{
			"cloudformation:CreateStack",
			"cloudformation:UpdateStack",
			"cloudformation:CreateChangeSet",
		},
	},
}

// resolveServiceExecChains scans the principal's effective allows
// for the service-execution privesc primitive: iam:PassRole on a
// role whose trust policy allows a managed service principal,
// PLUS any trigger action that drives the service to assume that
// role on the caller's behalf. Each (principal, role, primitive)
// triple emits a single-hop chain.
//
// V1 contract:
//   - Wildcard targets (Resource: "*") on iam:PassRole are skipped.
//     A "*" PassRole grant is itself a posture concern flagged by
//     the catalog's broad-permission controls; expanding "all roles
//     in the snapshot" here would explode the chain count without
//     improving precision.
//   - The trigger-action grant's resource scope is NOT cross-checked
//     against the role's resource scope. If P has lambda:InvokeFunction
//     on any function and PassRole on R, P can create a new function
//     attached to R as long as InvokeFunction permits it. v1
//     conservatively accepts this; a future iteration can pair the
//     trigger action's resource with the function/task association.
//   - Multi-hop chains through service-execution edges are not
//     produced. The expected pattern is a single-hop pivot from a
//     limited principal to an admin execution role; transitive
//     pivots from that execution role would be picked up by the
//     assume-role walker.
func resolveServiceExecChains(input RoleChainInput) []RoleChain {
	resolved, _, ok := lookupResolved(input.ResolvedIndex, input.PrincipalARN)
	if !ok {
		return nil
	}
	var chains []RoleChain

	for _, primitive := range serviceExecPrimitives {
		hasTrigger := principalHasAnyAction(resolved, primitive.TriggerActions)
		if !hasTrigger {
			continue
		}
		for _, grant := range resolved.EffectiveAllow {
			if !isPassRoleAction(grant.Action) {
				continue
			}
			targetARN := grant.Resource
			if targetARN == "" || targetARN == "*" {
				continue
			}
			if !roleTrustsService(input.ServiceTrusts, targetARN, primitive.ServicePrincipal) {
				continue
			}

			var level PrivilegeLevel
			targetResolved, canonicalTargetARN, inSnapshot := lookupResolved(input.ResolvedIndex, targetARN)
			if inSnapshot {
				level = targetResolved.PrivilegeLevel
				targetARN = canonicalTargetARN
			}

			hop := RoleHop{
				FromARN:        input.PrincipalARN,
				ToARN:          targetARN,
				IsCrossAccount: !principalInAccount(targetARN, input.AccountID),
				Type:           primitive.HopType,
			}
			chains = append(chains, RoleChain{
				Hops:            []RoleHop{hop},
				FinalRoleARN:    targetARN,
				TransitiveLevel: level,
			})
		}
	}
	return chains
}

func principalHasAnyAction(resolved *ResolvedPermissions, candidates []string) bool {
	candidateSet := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		candidateSet[strings.ToLower(c)] = struct{}{}
	}
	for _, grant := range resolved.EffectiveAllow {
		lower := strings.ToLower(grant.Action)
		if _, ok := candidateSet[lower]; ok {
			return true
		}
		if lower == "*" {
			return true
		}
		if isWildcardServicePrefix(grant.Action, candidates) {
			return true
		}
	}
	return false
}

// isWildcardServicePrefix reports whether grantAction is a
// service-wildcard form (e.g. "lambda:*") that covers any of the
// candidates. Centralised here so the per-primitive trigger checks
// don't reimplement the prefix dance.
func isWildcardServicePrefix(grantAction string, candidates []string) bool {
	lowerGrant := strings.ToLower(grantAction)
	if !strings.HasSuffix(lowerGrant, ":*") {
		return false
	}
	prefix := strings.TrimSuffix(lowerGrant, ":*")
	for _, candidate := range candidates {
		if strings.HasPrefix(strings.ToLower(candidate), prefix+":") {
			return true
		}
	}
	return false
}

func isPassRoleAction(action string) bool {
	lower := strings.ToLower(action)
	return lower == "iam:passrole" || lower == "iam:*" || lower == "*"
}

func roleTrustsService(serviceTrusts map[string][]string, roleARN, servicePrincipal string) bool {
	services, _, ok := lookupServiceTrusts(serviceTrusts, roleARN)
	if !ok {
		return false
	}
	for _, svc := range services {
		if strings.EqualFold(svc, servicePrincipal) {
			return true
		}
	}
	return false
}

// invokeExistingPrimitive describes one (service-kind → trigger-
// actions → hop-kind) triple for the Iter 6 invoke-existing
// walker. Distinct from Iter 3's serviceExecPrimitives because:
//   - Iter 3 requires iam:PassRole on the target role; the role
//     binding is established by the attack itself.
//   - Iter 6 needs only the trigger action on the SPECIFIC
//     resource ARN; the binding pre-existed the attack.
//
// Trigger actions here are the SUBSET of Iter 3's table that
// invoke / mutate an existing resource without re-binding its
// role. Create-shaped actions (CreateFunction, CreateStack) are
// EXCLUDED — those are Iter 3's territory.
type invokeExistingPrimitive struct {
	HopType        HopType
	ServiceKind    string
	TriggerActions []string
}

// invokeExistingPrimitives lists the v1 confused-deputy primitives.
// Lambda + CloudFormation cover the gap-prompt example explicitly;
// other services (ECS RunTask on existing task definitions,
// CodeBuild StartBuild on existing projects, Glue StartJobRun on
// existing jobs) follow the same pattern and can be added by
// extending this slice plus the resourceBindingExtractors table.
var invokeExistingPrimitives = []invokeExistingPrimitive{
	{
		HopType:     HopTypeLambdaInvokeExisting,
		ServiceKind: "lambda",
		TriggerActions: []string{
			"lambda:InvokeFunction",
			// UpdateFunctionCode redeploys an attacker payload
			// against the existing role binding without changing
			// the role.
			"lambda:UpdateFunctionCode",
		},
	},
	{
		HopType:     HopTypeCfnUpdateExisting,
		ServiceKind: "cloudformation",
		TriggerActions: []string{
			// UpdateStack against an existing stack reuses the
			// stack's pre-bound execution role; no PassRole needed.
			"cloudformation:UpdateStack",
			"cloudformation:CreateChangeSet",
			"cloudformation:ExecuteChangeSet",
		},
	},
}

// resolveExistingResourceInvocations scans the principal's
// effective allows for trigger actions on SPECIFIC resource ARNs
// whose snapshot binding names a role that is itself in the
// snapshot. Each (principal, resource, role) triple emits a
// single-hop chain.
//
// V1 contract:
//   - Wildcard targets (Resource: "*") on the trigger action are
//     NOT enumerated. A wildcard grant against EVERY function /
//     stack would explode the chain count and obscures the
//     specific resource at fault. Wildcard trigger grants surface
//     through Iter 3's create-and-pass walker plus the catalog's
//     broad-permission controls — different concern.
//   - The role binding must be observable in the snapshot. If a
//     function is bound to a role outside the snapshot, the
//     walker has no privilege level to attribute and skips.
//   - Multi-hop chains through invoke-existing edges are not
//     produced. Pivoting from the bound role's permissions onto
//     another role is the assume walker's job.
func resolveExistingResourceInvocations(input RoleChainInput) []RoleChain {
	resolved, _, ok := lookupResolved(input.ResolvedIndex, input.PrincipalARN)
	if !ok {
		return nil
	}
	if len(input.ResourceRoleBindings) == 0 {
		return nil
	}
	var chains []RoleChain

	for _, primitive := range invokeExistingPrimitives {
		for _, grant := range resolved.EffectiveAllow {
			if !triggerActionMatches(grant.Action, primitive.TriggerActions) {
				continue
			}
			if grant.Resource == "" || grant.Resource == "*" {
				continue
			}
			binding, _, hasBinding := lookupResourceRoleBinding(input.ResourceRoleBindings, grant.Resource)
			if !hasBinding {
				continue
			}
			if binding.ServiceKind != primitive.ServiceKind {
				continue
			}
			targetRoleARN := binding.RoleARN
			targetResolved, canonicalTargetRoleARN, inSnapshot := lookupResolved(input.ResolvedIndex, targetRoleARN)
			if !inSnapshot {
				continue
			}
			hop := RoleHop{
				FromARN:        input.PrincipalARN,
				ToARN:          canonicalTargetRoleARN,
				IsCrossAccount: !principalInAccount(canonicalTargetRoleARN, input.AccountID),
				Type:           primitive.HopType,
			}
			chains = append(chains, RoleChain{
				Hops:            []RoleHop{hop},
				FinalRoleARN:    canonicalTargetRoleARN,
				TransitiveLevel: targetResolved.PrivilegeLevel,
			})
		}
	}
	return chains
}

// triggerActionMatches reports whether grantAction (an entry in
// the principal's resolved allows) covers any of the candidate
// trigger actions. Honors AWS wildcard semantics for management
// services: an exact match, the "*" total wildcard, or the
// service-prefix `lambda:*` style wildcard all activate the
// primitive. Centralised so the invoke-existing walker shares the
// same matching as the create-and-pass walker without duplicating
// the prefix dance.
func triggerActionMatches(grantAction string, candidates []string) bool {
	lower := strings.ToLower(grantAction)
	for _, c := range candidates {
		if strings.EqualFold(c, lower) {
			return true
		}
	}
	if lower == "*" {
		return true
	}
	return isWildcardServicePrefix(grantAction, candidates)
}

func resolveChainRecursive(
	input RoleChainInput,
	currentARN string,
	visited sets.Set[string],
	depth int,
	currentHops []RoleHop,
	chains *[]RoleChain,
) {
	if len(*chains) >= MaxChainsPerPrincipal {
		return
	}

	if depth >= MaxChainDepth {
		*chains = append(*chains, RoleChain{
			Hops:              cloneHops(currentHops),
			FinalRoleARN:      currentARN,
			TerminationReason: ChainTerminatedMaxDepth,
		})
		return
	}

	if visited.Contains(currentARN) {
		*chains = append(*chains, RoleChain{
			Hops:              cloneHops(currentHops),
			FinalRoleARN:      currentARN,
			TerminationReason: ChainTerminatedCycle,
		})
		return
	}

	visited.Add(currentARN)
	defer func() { delete(visited, currentARN) }()

	// Get resolved permissions for this principal.
	resolved, _, ok := lookupResolved(input.ResolvedIndex, currentARN)
	if !ok {
		return // principal not resolved — can't determine assumable roles
	}

	// Deduplicate target ARNs before recursing. A principal that
	// has the same role granted via multiple statements (or the
	// same role granted by both inline and managed policies) used
	// to recurse once per duplicate. Since visited.Add fires inside
	// the recursive call, the second occurrence of the same target
	// at the same depth tripped the cycle guard and emitted a
	// spurious ChainTerminatedCycle entry — even though it was a
	// duplicate grant, not a real cycle. Dedup at this level so
	// only genuine cycles (target reappearing along the same path)
	// surface as ChainTerminatedCycle.
	targets := sets.New[string]()

	// Find sts:Assume* grants in effective allows. Iter 3
	// extends the action set from {AssumeRole, sts:*, *} to also
	// include AssumeRoleWithWebIdentity (Cognito, federated OIDC)
	// and AssumeRoleWithSAML (federated SAML). The hop kind is
	// the same — a principal admitted into a role's identity —
	// only the action verb varies.
	for _, grant := range resolved.EffectiveAllow {
		if !isAssumeRoleAction(grant.Action) {
			continue
		}

		// The resource scope identifies which roles can be assumed.
		targetARN := grant.Resource
		if targetARN == "*" {
			// Wildcard AssumeRole — in practice this would enumerate all roles.
			// For performance, skip wildcard expansion (flagged by existing
			// CTL.IAM.POLICY.ASSUMEROLE.001 control).
			continue
		}
		if targets.Contains(targetARN) {
			continue
		}
		targets.Add(targetARN)

		// Check if the target role is in the snapshot.
		targetResolved, canonicalTargetARN, inSnapshot := lookupResolved(input.ResolvedIndex, targetARN)
		if !inSnapshot {
			*chains = append(*chains, RoleChain{
				Hops:              appendHop(currentHops, currentARN, targetARN, input.AccountID),
				FinalRoleARN:      targetARN,
				TerminationReason: ChainTerminatedNotInSnapshot,
			})
			continue
		}

		// Check trust policy — target role must trust the current
		// principal. Two channels:
		//   - PolicyDocument: principals encoded in stmt.Resource by
		//     the test-fixture and legacy parser path.
		//   - AWSPrincipalTrusts: the Iter-4 side-channel that probes
		//     raw trust JSON for `Principal: AWS: ...` entries the
		//     iam.Statement parser drops, including the account-root
		//     pattern that admits every principal in a named account.
		// Either channel admitting the assumer is sufficient.
		trustPolicy, _, _ := lookupTrustPolicy(input.TrustPolicies, canonicalTargetARN)
		awsTrust, _, _ := lookupAWSPrincipalTrusts(input.AWSPrincipalTrusts, canonicalTargetARN)
		if !trustAllowsAssumer(trustPolicy, awsTrust, currentARN) {
			continue // assumption not reciprocated
		}

		// Record this hop.
		newHops := appendHop(currentHops, currentARN, canonicalTargetARN, input.AccountID)

		// Record the chain with the target role's permissions.
		*chains = append(*chains, RoleChain{
			Hops:            cloneHops(newHops),
			FinalRoleARN:    canonicalTargetARN,
			TransitiveLevel: targetResolved.PrivilegeLevel,
		})

		// Recurse into the target role's chains.
		resolveChainRecursive(input, canonicalTargetARN, visited, depth+1, newHops, chains)
	}
}

// trustPolicyAllows checks if a role's trust policy allows assumption
// by the given principal ARN.
func trustPolicyAllows(trustPolicy *PolicyDocument, principalARN string) bool {
	if trustPolicy == nil {
		return false
	}
	allows := trustPolicy.Allows()
	for i := range allows {
		if !slices.ContainsFunc(allows[i].Action, isAssumeRoleAction) {
			continue
		}
		for _, r := range allows[i].Resource {
			if r == "*" {
				return true
			}
			if r == principalARN {
				return true
			}
			if actionMatches(r, principalARN) {
				return true
			}
		}
	}
	return false
}

// trustAllowsAssumer reports whether either the parsed trust
// policy OR the side-channel AWS-principal trust expansion admits
// principalARN as an assumer. A bare-Principal:"*" wildcard is
// honored the same way the parsed-policy path does (Resource:"*"
// returns true above).
//
// The two channels are unioned because each captures a different
// slice of the real-world surface:
//   - trustPolicyAllows walks stmt.Resource; that field carries
//     principals for legacy / test-fixture trust documents
//     constructed via the trustDoc(...) helper.
//   - awsPrincipalTrust comes from a raw-JSON probe and captures
//     real AWS trust shapes (`Principal: AWS: arn::root`,
//     `Principal: AWS: <12-digit account>`, exact-ARN trust)
//     that the Statement parser drops.
//
// Trust expansion in v1 covers account-root and exact-ARN
// principals. ConditionalOrgID-bounded wildcards are left for a
// future iteration; the bare top-level Principal:"*" wildcard
// IS honored here because it is unambiguous.
func trustAllowsAssumer(trustPolicy *PolicyDocument, awsPrincipalTrust AWSTrustedPrincipals, principalARN string) bool {
	if trustPolicy != nil && trustPolicyAllows(trustPolicy, principalARN) {
		return true
	}
	return awsPrincipalTrustAdmits(awsPrincipalTrust, principalARN)
}

// awsPrincipalTrustAdmits reports whether the side-channel
// expansion alone admits principalARN. Split out so unit tests
// can pin the side-channel logic without staging a full
// PolicyDocument.
func awsPrincipalTrustAdmits(t AWSTrustedPrincipals, principalARN string) bool {
	if t.Wildcard {
		return true
	}
	if slices.Contains(t.ExactARNs, principalARN) {
		return true
	}
	if len(t.AccountRoots) == 0 {
		return false
	}
	principalAcct := ExtractAccountIDFromARN(principalARN)
	if principalAcct == "" {
		return false
	}
	return slices.Contains(t.AccountRoots, principalAcct)
}

// HasTransitiveAdmin checks if any chain reaches admin-equivalent permissions.
func HasTransitiveAdmin(chains []RoleChain) bool {
	for _, chain := range chains {
		if chain.TerminationReason != ChainTerminatedNormal {
			continue
		}
		if chain.TransitiveLevel == PrivilegeLevelAdmin {
			return true
		}
	}
	return false
}

// MaxDepth returns the deepest chain depth found.
func MaxDepth(chains []RoleChain) int {
	maxDepth := 0
	for _, chain := range chains {
		if len(chain.Hops) > maxDepth {
			maxDepth = len(chain.Hops)
		}
	}
	return maxDepth
}

func appendHop(hops []RoleHop, from, to, accountID string) []RoleHop {
	newHops := cloneHops(hops)
	return append(newHops, RoleHop{
		FromARN:        from,
		ToARN:          to,
		IsCrossAccount: !principalInAccount(to, accountID),
		Type:           HopTypeAssume,
	})
}

// resolveTagMutationChains scans the principal's effective allows
// for IAM tag-mutation actions. When the principal can tag a role
// AND that role's trust policy is conditional on aws:ResourceTag/*,
// the principal can self-tag the role to satisfy the trust
// condition and then assume it — a single-hop ABAC privesc edge.
//
// V1 contract:
//   - One chain per (principal, target-role) pair where the
//     primitive is feasible. No multi-hop expansion through
//     tag-mutation hops; the v1 use case is "principal tags a
//     directly-reachable role".
//   - The chain's TransitiveLevel reflects the target role's
//     privilege classification (the post-tag-and-assume access).
//   - Cross-account flag matches the assume-walker semantics:
//     true when the target ARN's account differs from the
//     starting principal's account.
//
// Detection is intentionally conservative ON THE TAG-CONDITION
// SIDE (any aws:ResourceTag/* / aws:RequestTag/* / aws:TagKeys
// reference in the trust policy fires) and conservative ON THE
// PERMISSION SIDE (only iam:Tag* / iam:Untag* / iam:* / *
// counted; iam:CreateRole + reset-trust would be a separate
// primitive worth a future pass).
func resolveTagMutationChains(input RoleChainInput) []RoleChain {
	resolved, _, ok := lookupResolved(input.ResolvedIndex, input.PrincipalARN)
	if !ok {
		return nil
	}
	seen := sets.New[string]()
	var chains []RoleChain

	for _, grant := range resolved.EffectiveAllow {
		if !isTagMutationAction(grant.Action) {
			continue
		}
		targetARN := grant.Resource
		if targetARN == "" || targetARN == "*" {
			// Wildcard tagging — same v1 deferral as wildcard
			// AssumeRole. Flag as a posture concern via
			// CTL.IAM.POLICY.* controls, not as enumerated
			// chains.
			continue
		}
		if seen.Contains(targetARN) {
			continue
		}
		seen.Add(targetARN)

		trustPolicy, canonicalTargetARN, hasTrust := lookupTrustPolicy(input.TrustPolicies, targetARN)
		if !hasTrust || !trustPolicyHasTagCondition(trustPolicy) {
			continue
		}

		targetResolved, _, inSnapshot := lookupResolved(input.ResolvedIndex, canonicalTargetARN)
		var level PrivilegeLevel
		if inSnapshot {
			level = targetResolved.PrivilegeLevel
		}

		hop := RoleHop{
			FromARN:        input.PrincipalARN,
			ToARN:          canonicalTargetARN,
			IsCrossAccount: !principalInAccount(canonicalTargetARN, input.AccountID),
			Type:           HopTypeTagMutation,
		}
		chains = append(chains, RoleChain{
			Hops:            []RoleHop{hop},
			FinalRoleARN:    canonicalTargetARN,
			TransitiveLevel: level,
		})
	}
	return chains
}

// isTagMutationAction recognises the IAM actions that let a
// principal mutate the target role's tag set. Granting any of
// these on a role is the necessary half of the ABAC privesc
// primitive; the trust-policy half is checked separately.
func isTagMutationAction(action string) bool {
	switch strings.ToLower(action) {
	case "iam:tagrole", "iam:untagrole",
		"iam:taguser", "iam:untaguser",
		"iam:tagpolicy", "iam:untagpolicy",
		"iam:*", "*":
		return true
	}
	return false
}

// trustPolicyHasTagCondition reports whether ANY allow statement
// in the trust policy references an aws:ResourceTag/*,
// aws:RequestTag/*, or aws:TagKeys condition key. Iter 2's v1:
// the WAY the tag is used (StringEquals matching a literal,
// StringLike with a wildcard, etc.) is not analysed — any tag
// reference fires the privesc detection. Defenders typically
// want the over-approximation; the false-positive rate stays
// low because tag-conditional trust policies are uncommon
// outside the deliberate ABAC pattern this primitive exploits.
func trustPolicyHasTagCondition(policy *PolicyDocument) bool {
	if policy == nil {
		return false
	}
	allows := policy.Allows()
	for i := range allows {
		if conditionReferencesTag(allows[i].Condition) {
			return true
		}
	}
	return false
}

// conditionReferencesTag walks the (untyped) Condition map of an
// IAM statement looking for tag-relevant condition keys.
// Tolerates the standard map[op]map[key]value shape the IAM
// package emits without normalisation; anything else returns
// false.
func conditionReferencesTag(rawCondition any) bool {
	conds, ok := rawCondition.(map[string]any)
	if !ok || len(conds) == 0 {
		return false
	}
	for _, byKey := range conds {
		keyMap, ok := byKey.(map[string]any)
		if !ok {
			continue
		}
		for key := range keyMap {
			if isTagConditionKey(key) {
				return true
			}
		}
	}
	return false
}

func isTagConditionKey(key string) bool {
	lower := strutil.ToLowerTrim(key)
	if lower == "aws:tagkeys" {
		return true
	}
	if strings.HasPrefix(lower, "aws:resourcetag/") {
		return true
	}
	if strings.HasPrefix(lower, "aws:requesttag/") {
		return true
	}
	if strings.HasPrefix(lower, "aws:principaltag/") {
		return true
	}
	return false
}

func cloneHops(hops []RoleHop) []RoleHop {
	if hops == nil {
		return nil
	}
	out := make([]RoleHop, len(hops))
	copy(out, hops)
	return out
}

func lookupResolved(m map[string]*ResolvedPermissions, key string) (*ResolvedPermissions, string, bool) {
	if val, ok := m[key]; ok {
		return val, key, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, k, true
		}
	}
	return nil, "", false
}

func lookupTrustPolicy(m map[string]*PolicyDocument, key string) (*PolicyDocument, string, bool) {
	if val, ok := m[key]; ok {
		return val, key, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, k, true
		}
	}
	return nil, "", false
}

func lookupAWSPrincipalTrusts(m map[string]AWSTrustedPrincipals, key string) (AWSTrustedPrincipals, string, bool) {
	if val, ok := m[key]; ok {
		return val, key, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, k, true
		}
	}
	return AWSTrustedPrincipals{}, "", false
}

func lookupDeletion(m map[string]time.Time, key string) (time.Time, bool) {
	if val, ok := m[key]; ok {
		return val, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return time.Time{}, false
}

func lookupServiceTrusts(m map[string][]string, key string) ([]string, string, bool) {
	if val, ok := m[key]; ok {
		return val, key, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, k, true
		}
	}
	return nil, "", false
}

func lookupResourceRoleBinding(m map[string]ResourceRoleBinding, key string) (ResourceRoleBinding, string, bool) {
	if val, ok := m[key]; ok {
		return val, key, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, k, true
		}
	}
	return ResourceRoleBinding{}, "", false
}
