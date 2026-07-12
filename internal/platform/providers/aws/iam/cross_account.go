package iam

import (
	"strings"

	"github.com/sufield/stave/internal/core/access"
)

// resourceGrant is the inverted view of a resource access entry:
// one resource's grant to one principal.
type resourceGrant struct {
	resourceARN    string
	actions        []string
	isCrossAccount bool
	isPublic       bool
}

// applyResourcePolicyGrants populates ResourcePolicyGrants on each
// ResolvedPermissions using the cross-account permission formula:
//
//	Same-account:  identity ∨ resource_policy (resource grant always included)
//	Cross-account: identity ∧ resource_policy (resource grant only if identity also allows)
//	Public:        always included (accessible to all principals)
func applyResourcePolicyGrants(resolved map[string]*ResolvedPermissions, idx *access.ResourceAccessIndex) {
	byPrincipal := invertIndex(idx)
	for principalARN, grants := range byPrincipal {
		perms, ok := resolved[principalARN]
		if !ok {
			continue
		}
		for _, g := range grants {
			if g.isPublic || !g.isCrossAccount {
				perms.ResourcePolicyGrants = append(perms.ResourcePolicyGrants, ResourcePolicyGrant{
					ResourceARN:    g.resourceARN,
					Actions:        g.actions,
					IsCrossAccount: g.isCrossAccount,
					IsPublic:       g.isPublic,
				})
				continue
			}
			allowed := filterByIdentityAllows(g.actions, perms.EffectiveAllow)
			if len(allowed) > 0 {
				perms.ResourcePolicyGrants = append(perms.ResourcePolicyGrants, ResourcePolicyGrant{
					ResourceARN:    g.resourceARN,
					Actions:        allowed,
					IsCrossAccount: true,
				})
			}
		}
	}
}

// invertIndex builds a principal → grants map from the resource-keyed index.
func invertIndex(idx *access.ResourceAccessIndex) map[string][]resourceGrant {
	out := make(map[string][]resourceGrant)
	idx.Range(func(resourceID string, entry access.ResourceAccessEntry) {
		out[entry.PrincipalARN] = append(out[entry.PrincipalARN], resourceGrant{
			resourceARN:    resourceID,
			actions:        entry.Actions,
			isCrossAccount: entry.IsCrossAccount,
			isPublic:       entry.IsPublic,
		})
	})
	return out
}

// filterByIdentityAllows returns only those actions from a resource
// policy grant that the principal's identity policy also allows.
func filterByIdentityAllows(resourceActions []string, identityAllows []ActionGrant) []string {
	identityActions := make(map[string]struct{}, len(identityAllows))
	for _, g := range identityAllows {
		identityActions[g.Action] = struct{}{}
	}
	var allowed []string
	for _, action := range resourceActions {
		if _, ok := identityActions[action]; ok {
			allowed = append(allowed, action)
			continue
		}
		if matchesWildcardAction(action, identityActions) {
			allowed = append(allowed, action)
		}
	}
	return allowed
}

// matchesWildcardAction checks if any identity action covers the
// given resource action via wildcard (full * or service:*).
func matchesWildcardAction(action string, identityActions map[string]struct{}) bool {
	if _, ok := identityActions["*"]; ok {
		return true
	}
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		if _, ok := identityActions[parts[0]+":*"]; ok {
			return true
		}
	}
	return false
}
