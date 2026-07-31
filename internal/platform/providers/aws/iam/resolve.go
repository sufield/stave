package iam

import (
	"strings"

	coreiam "github.com/sufield/stave/internal/core/iam"
)

// PrivilegeLevel classifies the resolved effective permission set.
type PrivilegeLevel string

const (
	PrivilegeLevelUnknown  PrivilegeLevel = "unknown"
	PrivilegeLevelNone     PrivilegeLevel = "none"
	PrivilegeLevelLimited  PrivilegeLevel = "limited"
	PrivilegeLevelStandard PrivilegeLevel = "standard"
	PrivilegeLevelElevated PrivilegeLevel = "elevated"
	PrivilegeLevelAdmin    PrivilegeLevel = "admin"
)

// ActionGrant represents a resolved allowed (or denied) action
// with its source. Used uniformly for the Allow side
// (EffectiveAllow) and the Deny side (ExplicitDeny) of resolution.
//
// Conditions carries the raw Condition block from the originating
// statement, when present. nil means an unconditioned grant; a
// non-empty value means the grant is scoped to a subset of
// principals/contexts and consumers must respect that scope.
//
// Iter 7 (scoped Deny): the Deny-coverage check honors Conditions.
// Pre-Iter-7 the field was unused, so existing call sites that
// emit ActionGrant literals without it default to nil — which is
// the correct fallback for unconditioned grants and identical to
// pre-Iter-7 behavior.
type ActionGrant struct {
	Action       string
	NotActions   []string // inverse of Action; mutually exclusive with Action
	Resource     string
	NotResources []string // inverse of Resource; mutually exclusive with Resource
	Source       string   // policy ARN or description
	Conditions   any      // raw Condition block from the Statement; nil = unconditioned.
}

// ResolvedPermissions is the output of the policy resolution algorithm.
type ResolvedPermissions struct {
	PrincipalARN      string
	EffectiveAllow    []ActionGrant
	ExplicitDeny      []ActionGrant
	SCPBlocked        []string // actions blocked by SCP ceiling
	BoundaryBlocked   []string // actions blocked by boundary ceiling
	PrivilegeLevel    PrivilegeLevel
	IsAdmin           bool
	BoundaryEffective bool // true if boundary meaningfully constrains
	Incomplete        bool
	IncompleteReasons []string

	// Risk profile from sensitive action registry.
	RiskProfile RiskProfile

	// Iteration 2: resource-based policy grants
	ResourcePolicyGrants []ResourcePolicyGrant

	// Iteration 3: transitive role chain resolution
	RoleChains         []RoleChain
	MaxChainDepthVal   int
	HasTransitiveAdmin bool
}

// PrivilegeBucket returns the canonical lowercase bucket name the
// nep summary uses for its privilege-tier counters: "admin",
// "elevated", "standard", "limited", or "none". Replaces the
// inline switch on PrivilegeLevel that the summary loop used to
// reproduce.
func (r *ResolvedPermissions) PrivilegeBucket() string {
	if r == nil {
		return "none"
	}
	switch r.PrivilegeLevel {
	case PrivilegeLevelAdmin:
		return "admin"
	case PrivilegeLevelElevated:
		return "elevated"
	case PrivilegeLevelStandard:
		return "standard"
	case PrivilegeLevelLimited:
		return "limited"
	case PrivilegeLevelUnknown:
		return "unknown"
	default:
		return "none"
	}
}

// ResolutionInput holds the policy data for a single principal.
type ResolutionInput struct {
	PrincipalARN     string
	IdentityPolicies []PolicyDocument // managed + inline + group
	SCPHierarchy     []PolicyDocument // ordered root → account; nil = absent
	SCPPresent       bool             // false = absent from snapshot (incomplete)
	BoundaryPolicy   *PolicyDocument  // nil = no boundary attached
	BoundaryPresent  bool             // true = boundary exists but doc may be nil
	// MalformedLayers names policy layers that were PRESENT but failed to parse
	// (e.g. "identity policies", "scp", "boundary"). A malformed layer must NOT
	// be silently dropped — that under-scopes effective permissions. Resolve
	// folds this into Incomplete so downstream treats the result conservatively.
	MalformedLayers []string
}

// Resolve computes net effective permissions for a principal by applying
// all four policy layers: explicit denies, SCP ceiling, permission
// boundary ceiling, and identity-based allows.
//
// Known limitation: VPC endpoint policies are not modeled. These
// restrict which actions can transit a specific VPC endpoint,
// further constraining effective permissions below what the four
// layers here compute. Modeling them requires network topology
// (which endpoint a principal's traffic traverses), which is
// outside the scope of static snapshot analysis.
//
// Session policies (inline policies passed at assume-role time) are
// also out of scope. They are runtime constructs — the policy
// document is ephemeral and not captured in configuration snapshots.
//
// This is a pure function with no side effects.
func Resolve(input ResolutionInput) ResolvedPermissions {
	result := ResolvedPermissions{
		PrincipalARN: input.PrincipalARN,
	}

	// Check completeness.
	if len(input.MalformedLayers) > 0 {
		// A present-but-unparseable policy layer means the effective
		// permissions are under-scoped (a missing Deny/SCP looks more
		// permissive). Treat as inconclusive rather than trusting the result.
		result.Incomplete = true
		result.IncompleteReasons = append(result.IncompleteReasons,
			"policy layer(s) present but unparseable: "+strings.Join(input.MalformedLayers, ", "))
	}
	if !input.SCPPresent {
		result.Incomplete = true
		result.IncompleteReasons = append(result.IncompleteReasons,
			"org.scp_hierarchy absent from snapshot")
	}
	if input.BoundaryPresent && input.BoundaryPolicy == nil {
		result.Incomplete = true
		result.IncompleteReasons = append(result.IncompleteReasons,
			"permission boundary policy document absent from snapshot")
	}
	if result.Incomplete {
		result.PrivilegeLevel = PrivilegeLevelUnknown
		return result
	}

	// Layer 4: collect all identity-based allows.
	var identityAllows []ActionGrant
	for _, doc := range input.IdentityPolicies {
		allows := doc.Allows()
		for i := range allows {
			identityAllows = append(identityAllows, expandGrants(allows[i], "identity-based")...)
		}
	}

	// Layer 2: compute SCP ceiling (intersection of all SCP allows).
	scpCeiling := collectSCPCeiling(input.SCPHierarchy)

	// Layer 3: compute boundary ceiling.
	boundaryCeiling := collectBoundaryCeiling(input.BoundaryPolicy)

	// Layer 1: collect all explicit denies across all layers.
	explicitDenies := collectExplicitDenies(input)

	// Apply layers: effective = (identity ∩ scp ∩ boundary) - denies
	var effective []ActionGrant
	for _, grant := range identityAllows {
		if isExplicitlyDenied(grant, explicitDenies) {
			result.ExplicitDeny = append(result.ExplicitDeny, grant)
			continue
		}
		if !matchesCeiling(grant, scpCeiling) {
			result.SCPBlocked = append(result.SCPBlocked, grant.Action)
			continue
		}
		if !matchesCeiling(grant, boundaryCeiling) {
			result.BoundaryBlocked = append(result.BoundaryBlocked, grant.Action)
			continue
		}
		effective = append(effective, grant)
	}

	result.EffectiveAllow = effective
	result.PrivilegeLevel, result.RiskProfile = classifyPrivilege(effective)
	result.IsAdmin = result.PrivilegeLevel == PrivilegeLevelAdmin

	// Determine if boundary is effective (blocks at least one action).
	if input.BoundaryPolicy != nil {
		result.BoundaryEffective = len(result.BoundaryBlocked) > 0 &&
			!isTriviallyBroadBoundary(input.BoundaryPolicy)
	} else {
		// No boundary attached — boundary has no effect. Reporting
		// "effective" here misled control evaluators into treating an
		// unbounded principal as bounded, suppressing legitimate
		// privilege-escalation findings.
		result.BoundaryEffective = false
	}

	return result
}

// collectSCPCeiling computes the intersection of allowed actions
// across the SCP hierarchy. An action must be allowed by EVERY SCP
// in the chain — the previous flat-append shape produced the union,
// which let an action survive the ceiling whenever ANY SCP allowed
// it (a privilege-escalation hazard). An empty hierarchy (no org)
// means no ceiling; an empty intersection means everything is denied.
func collectSCPCeiling(scps []PolicyDocument) []ActionGrant {
	if len(scps) == 0 {
		return nil // nil means no ceiling
	}
	// Seed the ceiling with the first SCP's allows.
	ceiling := scpAllowGrants(scps[0])
	for i := 1; i < len(scps); i++ {
		next := scpAllowGrants(scps[i])
		ceiling = intersectGrants(ceiling, next)
		if len(ceiling) == 0 {
			// Once the intersection is empty, no later SCP can
			// add anything back — a deny-by-omission is the SCP
			// chain's strongest possible verdict.
			//
			// Return a non-nil empty slice, NOT nil. nil means
			// "no ceiling, everything passes" to matchesCeiling;
			// an empty-but-present ceiling must DENY everything.
			// Returning nil here let an action survive a chain
			// that allowed nothing in common — the exact
			// privilege-escalation hazard this intersection guards.
			return emptyCeiling()
		}
	}
	if len(ceiling) == 0 {
		// The hierarchy was present (len(scps) > 0) but its
		// running allow set is empty — same deny-everything verdict
		// as the in-loop collapse above. Never return nil here.
		return emptyCeiling()
	}
	return ceiling
}

// emptyCeiling is a non-nil, zero-length ActionGrant slice. It
// signals "a ceiling is present but admits no actions" — distinct
// from a nil ceiling, which means "no ceiling at all". matchesCeiling
// reports false for every grant against it, denying everything.
func emptyCeiling() []ActionGrant {
	return []ActionGrant{}
}

// scpAllowGrants flattens an SCP's Allow statements into the
// (action, resource) grant pairs collectSCPCeiling intersects.
func scpAllowGrants(doc PolicyDocument) []ActionGrant {
	allows := doc.Allows()
	var out []ActionGrant
	for i := range allows {
		out = append(out, expandGrants(allows[i], "scp allow")...)
	}
	return out
}

// intersectGrants returns the grants allowed by BOTH inputs, honoring
// wildcard subsumption rather than exact (action, resource) equality. A
// grant from one side is in the intersection when the other side covers it
// under matchesCeiling's wildcard semantics; the more specific of two
// overlapping grants is kept. This is what makes the AWS-default
// FullAWSAccess SCP behave correctly: {"*","*"} ∩ {s3:GetObject} =
// {s3:GetObject}, not the empty (deny-everything) set an exact-pair
// intersection produced. Two genuinely disjoint allow sets still intersect
// to empty.
func intersectGrants(a, b []ActionGrant) []ActionGrant {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	type grantKey struct {
		Action   string
		Resource string
	}
	var out []ActionGrant
	seen := make(map[grantKey]struct{})
	for _, ga := range a {
		for _, gb := range b {
			act, actOk := intersectAction(ga.Action, gb.Action)
			res, resOk := intersectResource(ga.Resource, gb.Resource)
			if actOk && resOk {
				k := grantKey{act, res}
				if _, ok := seen[k]; !ok {
					seen[k] = struct{}{}
					out = append(out, ActionGrant{
						Action:   act,
						Resource: res,
					})
				}
			}
		}
	}
	return out
}

func intersectAction(p1, p2 string) (string, bool) {
	if p1 == "*" {
		return p2, true
	}
	if p2 == "*" {
		return p1, true
	}
	if strings.EqualFold(p1, p2) {
		return p1, true
	}
	p1Wild := len(p1) > 2 && p1[len(p1)-1] == '*'
	p2Wild := len(p2) > 2 && p2[len(p2)-1] == '*'
	if p1Wild && p2Wild {
		pref1 := p1[:len(p1)-1]
		pref2 := p2[:len(p2)-1]
		if len(pref1) >= len(pref2) && strings.HasPrefix(strings.ToLower(pref1), strings.ToLower(pref2)) {
			return p1, true
		}
		if len(pref2) >= len(pref1) && strings.HasPrefix(strings.ToLower(pref2), strings.ToLower(pref1)) {
			return p2, true
		}
		return "", false
	}
	if p1Wild {
		pref1 := p1[:len(p1)-1]
		if len(p2) >= len(pref1) && strings.EqualFold(p2[:len(pref1)], pref1) {
			return p2, true
		}
		return "", false
	}
	if p2Wild {
		pref2 := p2[:len(p2)-1]
		if len(p1) >= len(pref2) && strings.EqualFold(p1[:len(pref2)], pref2) {
			return p1, true
		}
		return "", false
	}
	return "", false
}

func intersectResource(r1, r2 string) (string, bool) {
	if r1 == "*" {
		return r2, true
	}
	if r2 == "*" {
		return r1, true
	}
	if r1 == r2 {
		return r1, true
	}
	r1Wild := len(r1) > 1 && r1[len(r1)-1] == '*'
	r2Wild := len(r2) > 1 && r2[len(r2)-1] == '*'
	if r1Wild && r2Wild {
		pref1 := r1[:len(r1)-1]
		pref2 := r2[:len(r2)-1]
		if strings.HasPrefix(pref1, pref2) {
			return r1, true
		}
		if strings.HasPrefix(pref2, pref1) {
			return r2, true
		}
		return "", false
	}
	if r1Wild {
		pref1 := r1[:len(r1)-1]
		if strings.HasPrefix(r2, pref1) {
			return r2, true
		}
		return "", false
	}
	if r2Wild {
		pref2 := r2[:len(r2)-1]
		if strings.HasPrefix(r1, pref2) {
			return r1, true
		}
		return "", false
	}
	return "", false
}

// collectBoundaryCeiling extracts the allowed actions from the permission
// boundary. nil boundary means no ceiling. A non-nil boundary with zero
// Allow statements returns emptyCeiling() (denies everything), matching
// AWS semantics where effective = identity ∩ boundary.
func collectBoundaryCeiling(boundary *PolicyDocument) []ActionGrant {
	if boundary == nil {
		return nil // nil means no ceiling
	}
	allows := boundary.Allows()
	var ceiling []ActionGrant
	for i := range allows {
		ceiling = append(ceiling, expandGrants(allows[i], "boundary allow")...)
	}
	if len(ceiling) == 0 {
		return emptyCeiling()
	}
	return ceiling
}

// collectExplicitDenies collects all Deny statements across all
// policy layers, preserving each statement's Condition block on
// the emitted ActionGrant tuples.
//
// Iter 7 (scoped Deny): conditions are now carried so the
// coverage check (isExplicitlyDenied) can recognize a Deny that
// is scoped to a subset of principals/contexts and decline to
// credit it as universally protective. Pre-Iter-7 the
// Action+Resource cross-product was emitted with no condition
// metadata, so a Deny with `Condition: aws:PrincipalOrgID =
// o-other-org` was treated as covering EVERY principal — false
// negatives for any caller in our org.
func collectExplicitDenies(input ResolutionInput) []ActionGrant {
	var denies []ActionGrant

	for _, doc := range input.IdentityPolicies {
		stmts := doc.Denies()
		for i := range stmts {
			denies = append(denies, expandDenyGrants(stmts[i], "identity-based deny")...)
		}
	}

	for _, doc := range input.SCPHierarchy {
		stmts := doc.Denies()
		for i := range stmts {
			denies = append(denies, expandDenyGrants(stmts[i], "scp deny")...)
		}
	}

	if input.BoundaryPolicy != nil {
		stmts := input.BoundaryPolicy.Denies()
		for i := range stmts {
			denies = append(denies, expandDenyGrants(stmts[i], "boundary deny")...)
		}
	}

	return denies
}

// isExplicitlyDenied checks if a grant is covered by any explicit
// deny. Action + Resource scope must match AND the Deny's
// Condition block must not narrow the scope below "every
// principal/context".
//
// Iter 7 (scoped Deny): the conservative v1 rule is that ANY
// Condition block on a Deny disqualifies it as universally
// protective. The reasoning mirrors Iter 1's condition encoder
// in reverse — Iter 1 fixed the false-positive case where
// conditioned Allows were credited as public; Iter 7 fixes the
// false-negative case where conditioned Denies are credited as
// blocking.
//
// Why conservative is correct here: the gap-closure premise per
// gap-prompt.md:8 is that Stave hides attack paths behind
// Denies that don't actually apply. If we cannot prove the
// Deny's condition holds for the attacker (which we cannot for
// principal-scoping keys like aws:PrincipalOrgID,
// aws:PrincipalArn, aws:SourceVpce), we surface the path. False
// positives are recoverable; false negatives let attackers slip
// through silently.
//
// V2 follow-up: recognize universally-applicable condition keys
// (aws:SecureTransport=true, certain Bool gates) and credit
// those Denies as still protective. Out of scope for v1.
func isExplicitlyDenied(grant ActionGrant, denies []ActionGrant) bool {
	for _, deny := range denies {
		if !grantCoversAction(deny, grant.Action) ||
			!grantCoversResource(deny, grant.Resource) {
			continue
		}
		if denyHasNarrowingConditions(deny.Conditions) {
			continue
		}
		return true
	}
	return false
}

// denyHasNarrowingConditions reports whether the Condition block
// makes the Deny scope-narrowed below "every principal". Treats
// any non-empty condition block as narrowing — the v1
// conservative rule. The argument is `any` because the parsed
// Statement type stores the Condition field as the raw decoded
// JSON value (string-keyed map of operator → key → values).
//
// nil and empty maps return false (unconditioned Deny).
func denyHasNarrowingConditions(raw any) bool {
	if raw == nil {
		return false
	}
	m, ok := raw.(map[string]any)
	if !ok {
		// Non-map shape (string, slice, etc.) on a Condition
		// block is malformed AWS JSON. Conservative: treat as
		// narrowing rather than crash on unexpected input.
		return true
	}
	return len(m) > 0
}

// matchesCeiling checks if a grant passes through a ceiling (SCP or boundary).
// nil ceiling means no restriction (all actions pass).
func matchesCeiling(grant ActionGrant, ceiling []ActionGrant) bool {
	if ceiling == nil {
		return true // no ceiling = everything passes
	}
	for _, allowed := range ceiling {
		if grantCoversAction(allowed, grant.Action) &&
			grantCoversResource(allowed, grant.Resource) {
			return true
		}
	}
	return false
}

// actionMatches checks if a pattern action covers a specific action.
// Supports * (all actions) and service:* (all actions for a service).
func actionMatches(pattern, target string) bool {
	if pattern == "*" {
		return true
	}
	if strings.EqualFold(pattern, target) {
		return true
	}
	// service:* matches service:anything
	if len(pattern) > 2 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if len(target) >= len(prefix) && strings.EqualFold(target[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// resourceMatches checks if a pattern resource covers a specific resource.
func resourceMatches(pattern, target string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == target {
		return true
	}
	// Simple suffix wildcard: arn:...:bucket/* matches arn:...:bucket/key
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if len(target) >= len(prefix) && target[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// grantCoversAction reports whether a grant (allow or deny) covers a
// target action. For positive grants (Action set), delegates to
// actionMatches. For negative grants (NotActions set), the grant covers
// every action NOT matched by any NotAction entry.
func grantCoversAction(g ActionGrant, target string) bool {
	if len(g.NotActions) > 0 {
		for _, na := range g.NotActions {
			if actionMatches(na, target) {
				return false
			}
		}
		return true
	}
	return actionMatches(g.Action, target)
}

// grantCoversResource reports whether a grant covers a target resource.
func grantCoversResource(g ActionGrant, target string) bool {
	if len(g.NotResources) > 0 {
		for _, nr := range g.NotResources {
			if resourceMatches(nr, target) {
				return false
			}
		}
		return true
	}
	return resourceMatches(g.Resource, target)
}

// expandGrants converts a statement's Action/NotAction × Resource/NotResource
// into ActionGrant entries. Used for both Allow and Deny statements on the
// allow side (identity, SCP ceiling, boundary ceiling).
func expandGrants(stmt Statement, source string) []ActionGrant {
	actions := stmt.Action
	notActions := stmt.NotAction
	resources := stmt.Resource
	notResources := stmt.NotResource

	switch {
	case len(notActions) > 0 && len(notResources) > 0:
		return []ActionGrant{{
			NotActions:   notActions,
			NotResources: notResources,
			Source:       source,
		}}
	case len(notActions) > 0:
		out := make([]ActionGrant, 0, len(resources))
		for _, r := range resources {
			out = append(out, ActionGrant{NotActions: notActions, Resource: r, Source: source})
		}
		return out
	case len(notResources) > 0:
		out := make([]ActionGrant, 0, len(actions))
		for _, a := range actions {
			out = append(out, ActionGrant{Action: a, NotResources: notResources, Source: source})
		}
		return out
	default:
		out := make([]ActionGrant, 0, len(actions)*max(len(resources), 1))
		for _, a := range actions {
			for _, r := range resources {
				out = append(out, ActionGrant{Action: a, Resource: r, Source: source})
			}
		}
		return out
	}
}

// expandDenyGrants is like expandGrants but preserves the Condition
// block, which isExplicitlyDenied uses to detect scope-narrowed Denies.
func expandDenyGrants(stmt Statement, source string) []ActionGrant {
	actions := stmt.Action
	notActions := stmt.NotAction
	resources := stmt.Resource
	notResources := stmt.NotResource
	cond := stmt.Condition

	switch {
	case len(notActions) > 0 && len(notResources) > 0:
		return []ActionGrant{{
			NotActions:   notActions,
			NotResources: notResources,
			Source:       source,
			Conditions:   cond,
		}}
	case len(notActions) > 0:
		out := make([]ActionGrant, 0, len(resources))
		for _, r := range resources {
			out = append(out, ActionGrant{NotActions: notActions, Resource: r, Source: source, Conditions: cond})
		}
		return out
	case len(notResources) > 0:
		out := make([]ActionGrant, 0, len(actions))
		for _, a := range actions {
			out = append(out, ActionGrant{Action: a, NotResources: notResources, Source: source, Conditions: cond})
		}
		return out
	default:
		out := make([]ActionGrant, 0, len(actions)*max(len(resources), 1))
		for _, a := range actions {
			for _, r := range resources {
				out = append(out, ActionGrant{Action: a, Resource: r, Source: source, Conditions: cond})
			}
		}
		return out
	}
}

// isTriviallyBroadBoundary checks if a boundary allows everything
// (iam:* or *:* on Resource: *).
func isTriviallyBroadBoundary(boundary *PolicyDocument) bool {
	if boundary == nil {
		return false
	}
	allows := boundary.Allows()
	for i := range allows {
		for _, action := range allows[i].Action {
			for _, resource := range allows[i].Resource {
				if resource == "*" && (action == "*" || action == "iam:*") {
					return true
				}
			}
		}
	}
	return false
}

// RiskProfile summarizes the sensitive action categories present
// in a principal's effective permissions.
type RiskProfile struct {
	CredentialExposure int `json:"credential_exposure"`
	DataAccess         int `json:"data_access"`
	PrivEsc            int `json:"priv_esc"`
	ResourceExposure   int `json:"resource_exposure"`
	Discovery          int `json:"discovery"`
}

var sensitiveActions = coreiam.DefaultRegistry()

// classifyPrivilege determines the privilege level from the effective
// action set and computes the risk profile.
func classifyPrivilege(effective []ActionGrant) (PrivilegeLevel, RiskProfile) {
	if len(effective) == 0 {
		return PrivilegeLevelNone, RiskProfile{}
	}

	hasAdmin := false
	hasElevated := false
	hasBroadDataAccess := false
	serviceCount := make(map[string]struct{})
	var profile RiskProfile

	for _, grant := range effective {
		action := strings.ToLower(grant.Action)

		// Count risk categories across all grants (not just broad ones).
		for _, cat := range sensitiveActions.Classify(action) {
			switch cat {
			case coreiam.ActionCredentialExposure:
				profile.CredentialExposure++
			case coreiam.ActionDataAccess:
				profile.DataAccess++
			case coreiam.ActionPrivEsc:
				profile.PrivEsc++
			case coreiam.ActionResourceExposure:
				profile.ResourceExposure++
			case coreiam.ActionDiscovery:
				profile.Discovery++
			}
		}

		if !isEffectivelyBroadResource(grant.Resource) {
			continue
		}

		// Admin indicators: full wildcard, iam:*, or IAM policy-
		// mutation actions. Uses the registry's PrivEsc category
		// for IAM-prefixed actions, plus iam:CreatePolicy (classified
		// as ResourceExposure in the registry but functionally admin
		// when on a broad resource). iam:PassRole and iam:CreateRole
		// are elevated, not admin — excluded via isIAMAdminAction.
		if action == "*" || action == "iam:*" || isIAMAdminAction(action) {
			hasAdmin = true
		}
		// Elevated indicators: PassRole, broad service wildcards,
		// financial commitment actions, or any registry PrivEsc action
		// on a broad resource.
		if action == "iam:passrole" || action == "iam:createrole" ||
			action == "ec2:*" || action == "s3:*" ||
			action == "lambda:*" || action == "kms:*" ||
			action == "ec2:purchasereservedinstancesoffering" ||
			action == "savingsplans:createsavingsplan" ||
			action == "ec2:modifyreservedinstances" ||
			action == "aws-marketplace:subscribe" {
			hasElevated = true
		}
		if !hasElevated && sensitiveActions.HasCredentialExposure(action) {
			hasElevated = true
		}
		if sensitiveActions.HasDataAccess(action) {
			hasBroadDataAccess = true
		}

		if idx := strings.IndexByte(action, ':'); idx > 0 {
			serviceCount[action[:idx]] = struct{}{}
		}
	}

	var level PrivilegeLevel
	switch {
	case hasAdmin:
		level = PrivilegeLevelAdmin
	case hasElevated:
		level = PrivilegeLevelElevated
	case len(serviceCount) > 2 || hasBroadDataAccess:
		level = PrivilegeLevelStandard
	default:
		level = PrivilegeLevelLimited
	}
	return level, profile
}

// isIAMAdminAction reports whether an IAM action grants admin-level
// privilege when applied to a broad resource. Combines the registry's
// PrivEsc category for IAM-prefixed actions with iam:CreatePolicy
// (ResourceExposure in the registry but functionally admin on *).
// Excludes iam:PassRole and iam:CreateRole — those are elevated, not
// admin, because they require a second step (service trigger or trust
// policy) to gain the target role's permissions.
func isIAMAdminAction(action string) bool {
	if !strings.HasPrefix(action, "iam:") {
		return false
	}
	if action == "iam:passrole" || action == "iam:createrole" {
		return false
	}
	if action == "iam:createpolicy" {
		return true
	}
	return sensitiveActions.HasPrivEsc(action)
}

// isEffectivelyBroadResource reports whether resource is wildcard-
// equivalent for privilege-classification purposes.
//
// True when:
//   - resource is "*" or "arn:aws:*"
//   - non-ARN wildcard (e.g. "mybucket*") — conservative
//   - ARN with trailing "*" where the wildcard covers the resource
//     type segment or higher (e.g. "arn:aws:s3:::*",
//     "arn:aws:iam::123:*")
//
// False when:
//   - no trailing "*" (specific resource)
//   - ARN with trailing "*" deep in the resource path (e.g.
//     "arn:aws:s3:::bucket/prefix/*") — targets a sub-path
//     within one resource, not the entire type
func isEffectivelyBroadResource(resource string) bool {
	if resource == "*" || resource == "arn:aws:*" {
		return true
	}
	if !strings.HasSuffix(resource, "*") {
		return false
	}
	if !strings.HasPrefix(resource, "arn:") {
		return true
	}
	// ARN: arn:partition:service:region:account:resourcetype/path
	// Count colon-separated segments before the wildcard. A wildcard
	// in segment ≤5 covers the resource type; deeper targets a
	// specific sub-path.
	beforeWild := resource[:strings.LastIndex(resource, "*")]
	return strings.Count(beforeWild, ":") < 6
}
