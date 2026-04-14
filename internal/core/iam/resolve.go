package iam

// PrivilegeLevel classifies the resolved effective permission set.
type PrivilegeLevel string

const (
	PrivilegeLevelNone     PrivilegeLevel = "none"
	PrivilegeLevelLimited  PrivilegeLevel = "limited"
	PrivilegeLevelStandard PrivilegeLevel = "standard"
	PrivilegeLevelElevated PrivilegeLevel = "elevated"
	PrivilegeLevelAdmin    PrivilegeLevel = "admin"
)

// ActionGrant represents a resolved allowed action with its source.
type ActionGrant struct {
	Action   string
	Resource string
	Source   string // policy ARN or description
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

// ResolutionInput holds the policy data for a single principal.
type ResolutionInput struct {
	PrincipalARN     string
	IdentityPolicies []PolicyDocument // managed + inline + group
	SCPHierarchy     []PolicyDocument // ordered root → account; nil = absent
	SCPPresent       bool             // false = absent from snapshot (incomplete)
	BoundaryPolicy   *PolicyDocument  // nil = no boundary attached
	BoundaryPresent  bool             // true = boundary exists but doc may be nil
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
		// No boundary attached — not ineffective, just absent.
		result.BoundaryEffective = true
	}

	return result
}

// collectSCPCeiling computes the set of allowed actions from the SCP
// hierarchy. An action must be allowed by ALL SCPs in the chain.
// An empty hierarchy (no org) means no ceiling — all actions are allowed.
func collectSCPCeiling(scps []PolicyDocument) []ActionGrant {
	if len(scps) == 0 {
		return nil // nil means no ceiling
	}
	var ceiling []ActionGrant
	for _, doc := range scps {
		for _, stmt := range doc.Allows() {
			for _, action := range stmt.Action {
				for _, resource := range stmt.Resource {
					ceiling = append(ceiling, ActionGrant{
						Action:   action,
						Resource: resource,
					})
				}
			}
		}
	}
	return ceiling
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

// collectExplicitDenies collects all Deny statements across all policy layers.
func collectExplicitDenies(input ResolutionInput) []ActionGrant {
	var denies []ActionGrant

	// Denies from identity policies.
	for _, doc := range input.IdentityPolicies {
		for _, stmt := range doc.Denies() {
			for _, action := range stmt.Action {
				for _, resource := range stmt.Resource {
					denies = append(denies, ActionGrant{
						Action:   action,
						Resource: resource,
						Source:   "identity-based deny",
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
						Action:   action,
						Resource: resource,
						Source:   "scp deny",
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
						Action:   action,
						Resource: resource,
						Source:   "boundary deny",
					})
				}
			}
		}
	}

	return denies
}

// isExplicitlyDenied checks if a grant is covered by any explicit deny.
func isExplicitlyDenied(grant ActionGrant, denies []ActionGrant) bool {
	for _, deny := range denies {
		if actionMatches(deny.Action, grant.Action) &&
			resourceMatches(deny.Resource, grant.Resource) {
			return true
		}
	}
	return false
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
	serviceCount := make(map[string]bool)

	for _, grant := range effective {
		if grant.Resource != "*" {
			continue // only broad-scope actions affect classification
		}

		action := grant.Action
		// Admin indicators
		if action == "*" || action == "iam:*" ||
			action == "iam:CreatePolicy" || action == "iam:PutUserPolicy" ||
			action == "iam:PutRolePolicy" || action == "iam:AttachUserPolicy" ||
			action == "iam:AttachRolePolicy" {
			hasAdmin = true
		}
		// Elevated indicators
		if action == "iam:PassRole" || action == "iam:CreateRole" ||
			action == "ec2:*" || action == "s3:*" ||
			action == "lambda:*" || action == "kms:*" {
			hasElevated = true
		}

		// Track service breadth
		if idx := indexByte(action, ':'); idx > 0 {
			serviceCount[action[:idx]] = true
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
