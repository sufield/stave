package iam

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

// RoleHop is one step in a transitive role assumption chain.
type RoleHop struct {
	FromARN        string
	ToARN          string
	IsCrossAccount bool
}

// RoleChain represents a transitive path from a principal to a final
// role via one or more sts:AssumeRole hops.
type RoleChain struct {
	Hops              []RoleHop
	FinalRoleARN      string
	TransitiveLevel   PrivilegeLevel
	TerminationReason ChainTerminationReason
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

	// AccountID of the starting principal, for cross-account detection.
	AccountID string
}

// ResolveChains computes all transitive role assumption paths reachable
// from the starting principal. Each chain is a sequence of hops ending
// at a role whose resolved permissions represent the transitive access
// gained through that path.
func ResolveChains(input RoleChainInput) []RoleChain {
	visited := make(map[string]bool)
	var chains []RoleChain
	resolveChainRecursive(input, input.PrincipalARN, visited, 0, nil, &chains)
	return chains
}

func resolveChainRecursive(
	input RoleChainInput,
	currentARN string,
	visited map[string]bool,
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

	if visited[currentARN] {
		*chains = append(*chains, RoleChain{
			Hops:              cloneHops(currentHops),
			FinalRoleARN:      currentARN,
			TerminationReason: ChainTerminatedCycle,
		})
		return
	}

	visited[currentARN] = true
	defer func() { delete(visited, currentARN) }()

	// Get resolved permissions for this principal.
	resolved, ok := input.ResolvedIndex[currentARN]
	if !ok {
		return // principal not resolved — can't determine assumable roles
	}

	// Find sts:AssumeRole grants in effective allows.
	for _, grant := range resolved.EffectiveAllow {
		if grant.Action != "sts:AssumeRole" && grant.Action != "sts:*" && grant.Action != "*" {
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

		// Check if the target role is in the snapshot.
		targetResolved, inSnapshot := input.ResolvedIndex[targetARN]
		if !inSnapshot {
			*chains = append(*chains, RoleChain{
				Hops:              appendHop(currentHops, currentARN, targetARN, input.AccountID),
				FinalRoleARN:      targetARN,
				TerminationReason: ChainTerminatedNotInSnapshot,
			})
			continue
		}

		// Check trust policy — target role must trust the current principal.
		trustPolicy, hasTrust := input.TrustPolicies[targetARN]
		if !hasTrust || !trustPolicyAllows(trustPolicy, currentARN) {
			continue // assumption not reciprocated
		}

		// Record this hop.
		newHops := appendHop(currentHops, currentARN, targetARN, input.AccountID)

		// Record the chain with the target role's permissions.
		*chains = append(*chains, RoleChain{
			Hops:            cloneHops(newHops),
			FinalRoleARN:    targetARN,
			TransitiveLevel: targetResolved.PrivilegeLevel,
		})

		// Recurse into the target role's chains.
		resolveChainRecursive(input, targetARN, visited, depth+1, newHops, chains)
	}
}

// trustPolicyAllows checks if a role's trust policy allows assumption
// by the given principal ARN.
func trustPolicyAllows(trustPolicy *PolicyDocument, principalARN string) bool {
	if trustPolicy == nil {
		return false
	}
	for _, stmt := range trustPolicy.Allows() {
		// Check if any action is sts:AssumeRole.
		hasAssumeAction := false
		for _, a := range stmt.Action {
			if a == "sts:AssumeRole" || a == "sts:*" || a == "*" {
				hasAssumeAction = true
				break
			}
		}
		if !hasAssumeAction {
			continue
		}

		// Check if principal is in the Resource list (trust policies use
		// Principal field, but our simplified model normalizes to Resource).
		for _, r := range stmt.Resource {
			if r == "*" {
				return true
			}
			if r == principalARN {
				return true
			}
			// Account-level trust: arn:aws:iam::<account>:root
			if actionMatches(r, principalARN) {
				return true
			}
		}
	}
	return false
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
	max := 0
	for _, chain := range chains {
		if len(chain.Hops) > max {
			max = len(chain.Hops)
		}
	}
	return max
}

func appendHop(hops []RoleHop, from, to, accountID string) []RoleHop {
	newHops := cloneHops(hops)
	return append(newHops, RoleHop{
		FromARN:        from,
		ToARN:          to,
		IsCrossAccount: !principalInAccount(to, accountID),
	})
}

func cloneHops(hops []RoleHop) []RoleHop {
	if hops == nil {
		return nil
	}
	out := make([]RoleHop, len(hops))
	copy(out, hops)
	return out
}
