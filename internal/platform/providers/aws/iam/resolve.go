package iam

import "strings"

// PrivilegeLevel classifies the resolved effective permission set.
type PrivilegeLevel string

const (
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
	Action     string
	Resource   string
	Source     string // policy ARN or description
	Conditions any    // raw Condition block from the Statement; nil = unconditioned.
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
		return result
	}

	// Layer 4: collect all identity-based allows.
	var identityAllows []ActionGrant
	for _, doc := range input.IdentityPolicies {
		for _, stmt := range doc.Allows() {
			for _, action := range stmt.Action {
				for _, resource := range stmt.Resource {
					identityAllows = append(identityAllows, ActionGrant{
						Action:   action,
						Resource: resource,
						Source:   "identity-based",
					})
				}
			}
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
	result.PrivilegeLevel = classifyPrivilege(effective)
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
	var out []ActionGrant
	for _, stmt := range doc.Allows() {
		for _, action := range stmt.Action {
			for _, resource := range stmt.Resource {
				out = append(out, ActionGrant{
					Action:   action,
					Resource: resource,
				})
			}
		}
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
	seen := make(map[ActionGrant]struct{}, len(a)+len(b))
	out := make([]ActionGrant, 0, len(a)+len(b))
	add := func(g ActionGrant) {
		if _, ok := seen[g]; ok {
			return
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	for _, g := range a {
		if matchesCeiling(g, b) {
			add(g)
		}
	}
	for _, g := range b {
		if matchesCeiling(g, a) {
			add(g)
		}
	}
	return out
}

// collectBoundaryCeiling extracts the allowed actions from the permission
// boundary. nil boundary means no ceiling.
func collectBoundaryCeiling(boundary *PolicyDocument) []ActionGrant {
	if boundary == nil {
		return nil // nil means no ceiling
	}
	var ceiling []ActionGrant
	for _, stmt := range boundary.Allows() {
		for _, action := range stmt.Action {
			for _, resource := range stmt.Resource {
				ceiling = append(ceiling, ActionGrant{
					Action:   action,
					Resource: resource,
				})
			}
		}
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

	// Denies from identity policies.
	for _, doc := range input.IdentityPolicies {
		for _, stmt := range doc.Denies() {
			for _, action := range stmt.Action {
				for _, resource := range stmt.Resource {
					denies = append(denies, ActionGrant{
						Action:     action,
						Resource:   resource,
						Source:     "identity-based deny",
						Conditions: stmt.Condition,
					})
				}
			}
		}
	}

	// Denies from SCPs.
	for _, doc := range input.SCPHierarchy {
		for _, stmt := range doc.Denies() {
			for _, action := range stmt.Action {
				for _, resource := range stmt.Resource {
					denies = append(denies, ActionGrant{
						Action:     action,
						Resource:   resource,
						Source:     "scp deny",
						Conditions: stmt.Condition,
					})
				}
			}
		}
	}

	// Denies from boundary.
	if input.BoundaryPolicy != nil {
		for _, stmt := range input.BoundaryPolicy.Denies() {
			for _, action := range stmt.Action {
				for _, resource := range stmt.Resource {
					denies = append(denies, ActionGrant{
						Action:     action,
						Resource:   resource,
						Source:     "boundary deny",
						Conditions: stmt.Condition,
					})
				}
			}
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
		if !actionMatches(deny.Action, grant.Action) ||
			!resourceMatches(deny.Resource, grant.Resource) {
			continue
		}
		if denyHasNarrowingConditions(deny.Conditions) {
			// Scope-narrowed Deny: we cannot prove it covers
			// this grant's principal context. Skip and keep
			// looking; another Deny in the list might match
			// unconditionally.
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
		if actionMatches(allowed.Action, grant.Action) &&
			resourceMatches(allowed.Resource, grant.Resource) {
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
	if pattern == target {
		return true
	}
	// service:* matches service:anything
	if len(pattern) > 2 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if len(target) >= len(prefix) && target[:len(prefix)] == prefix {
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

// isTriviallyBroadBoundary checks if a boundary allows everything
// (iam:* or *:* on Resource: *).
func isTriviallyBroadBoundary(boundary *PolicyDocument) bool {
	if boundary == nil {
		return false
	}
	for _, stmt := range boundary.Allows() {
		for _, action := range stmt.Action {
			for _, resource := range stmt.Resource {
				if resource == "*" && (action == "*" || action == "iam:*") {
					return true
				}
			}
		}
	}
	return false
}

// classifyPrivilege determines the privilege level from the effective
// action set.
func classifyPrivilege(effective []ActionGrant) PrivilegeLevel {
	if len(effective) == 0 {
		return PrivilegeLevelNone
	}

	hasAdmin := false
	hasElevated := false
	serviceCount := make(map[string]struct{})

	for _, grant := range effective {
		// A grant influences classification when its resource is
		// effectively broad: literal "*", "arn:aws:*", or a wildcard
		// that covers a whole service / account. The previous
		// (Resource != "*" → continue) shape silently dropped grants
		// like "arn:aws:s3:::*" or "arn:aws:iam::123:role/*", which
		// are functionally equivalent to "*" for privilege-
		// escalation purposes — letting an effective-admin grant
		// classify as no-privilege.
		if !isEffectivelyBroadResource(grant.Resource) {
			continue
		}

		// IAM action names are case-insensitive in AWS, and actions are
		// not case-normalized during resolution, so compare the indicator
		// sets against the lowercased action.
		action := strings.ToLower(grant.Action)
		// Admin indicators
		if action == "*" || action == "iam:*" ||
			action == "iam:createpolicy" || action == "iam:putuserpolicy" ||
			action == "iam:putrolepolicy" || action == "iam:attachuserpolicy" ||
			action == "iam:attachrolepolicy" {
			hasAdmin = true
		}
		// Elevated indicators
		if action == "iam:passrole" || action == "iam:createrole" ||
			action == "ec2:*" || action == "s3:*" ||
			action == "lambda:*" || action == "kms:*" {
			hasElevated = true
		}

		// Track service breadth
		if idx := indexByte(action, ':'); idx > 0 {
			serviceCount[action[:idx]] = struct{}{}
		}
	}

	switch {
	case hasAdmin:
		return PrivilegeLevelAdmin
	case hasElevated:
		return PrivilegeLevelElevated
	case len(serviceCount) > 2:
		return PrivilegeLevelStandard
	default:
		return PrivilegeLevelLimited
	}
}

func indexByte(s string, b byte) int {
	for i := range s {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// isEffectivelyBroadResource reports whether resource is wildcard-
// equivalent for privilege-classification purposes. A grant that
// targets "arn:aws:iam::123:role/*" or "arn:aws:s3:::*" is
// functionally identical to "*" when we ask "does this principal
// have admin?" — so classification must consider the same set of
// indicators against either form.
//
// True when:
//   - resource is "*" (the literal full wildcard)
//   - resource is "arn:aws:*" or any prefix that ends in "*" with
//     no further service / account narrowing (e.g. "arn:aws:s3:::*",
//     "arn:aws:iam::123:*", "arn:aws:iam::123:role/*")
//
// False when the resource names a specific ARN (no trailing "*"),
// because a single named bucket / role is a meaningfully smaller
// blast radius and shouldn't escalate the principal to admin.
func isEffectivelyBroadResource(resource string) bool {
	if resource == "*" || resource == "arn:aws:*" {
		return true
	}
	// Trailing "*" with at least one ARN segment intact — the wildcard
	// covers the rest of a service / account scope. Conservative
	// (over-classifies rather than under-classifies) so a future
	// scoped-down ARN catches less, not more.
	return resource != "" && resource[len(resource)-1] == '*'
}
