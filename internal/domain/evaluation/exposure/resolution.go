package exposure

import (
	"github.com/sufield/stave/internal/domain/kernel"
)

// ResolveEffectiveVisibility computes the final exposure state after applying governance blocks.
func ResolveEffectiveVisibility(identity, resource Visibility, gov GovernanceOverrides) EffectiveVisibility {
	mask := resolveMask(identity, resource, gov)

	res := EffectiveVisibility{
		Read:       mask.Has(PermRead),
		Write:      mask.Has(PermWrite),
		List:       mask.Has(PermList),
		Delete:     mask.Has(PermDelete),
		AdminRead:  mask.Has(PermMetadataRead),
		AdminWrite: mask.Has(PermMetadataWrite),
	}

	// Latency: Would this be public if Governance didn't block it?
	rawPublicRead := identity.Public.Read || resource.Public.Read
	res.IsLatent = rawPublicRead && !res.Read

	res.PrincipalScope = resolvePrincipalScope(identity, resource, mask)

	return res
}

// BuildVisibilityResult constructs the flattened "Fact" structure used for storage/diagnostics.
func BuildVisibilityResult(identity, resource Visibility, gov GovernanceOverrides) VisibilityResult {
	effective := ResolveEffectiveVisibility(identity, resource, gov)

	res := VisibilityResult{
		// Governance Status
		IdentityExposureBlocked: gov.BlockIdentityBoundPublicAccess,
		ResourceExposureBlocked: gov.BlockResourceBoundPublicAccess,

		// Effective Access
		PublicRead:   effective.Read,
		PublicWrite:  effective.Write,
		PublicList:   effective.List,
		PublicDelete: effective.Delete,
		PublicAdmin:  effective.AdminRead || effective.AdminWrite,

		// Origin Signals (Identity)
		ReadViaIdentity: identity.Public.Read,
		ListViaIdentity: identity.Public.List,

		// Origin Signals (Resource)
		ReadViaResource:  resource.Public.Read,
		WriteViaResource: resource.Public.Write && !gov.BlockResourceBoundPublicAccess,
		AdminViaResource: resource.Public.Admin && !gov.BlockResourceBoundPublicAccess,

		// Latent Signals
		LatentPublicRead: effective.IsLatent,
		LatentPublicList: identity.Public.List && !effective.List,
	}

	// Authenticated Access (Post-Governance)
	res.AuthenticatedRead = resolveAuthField(identity.Authenticated.Read, resource.Authenticated.Read, gov)
	res.AuthenticatedWrite = resolveAuthField(identity.Authenticated.Write, resource.Authenticated.Write, gov)
	res.AuthenticatedAdmin = resolveAuthField(identity.Authenticated.Admin, resource.Authenticated.Admin, gov)

	return res
}

// --- Internal Posture Logic ---

func resolveMask(identity, resource Visibility, gov GovernanceOverrides) Permission {
	var mask Permission
	if !gov.BlockIdentityBoundPublicAccess {
		mask |= identity.Public.ToMask()
	}
	if !gov.BlockResourceBoundPublicAccess {
		mask |= resource.Public.ToMask()
	}
	return mask
}

func resolvePrincipalScope(identity, resource Visibility, effective Permission) kernel.PrincipalScope {
	// 1. If any permission is effectively public, the scope is Public.
	if effective != 0 {
		return kernel.ScopePublic
	}

	// 2. If not public, but any authenticated access is permitted, the scope is Authenticated.
	// Note: We check raw authenticated fields here as they aren't part of the 'effective' bitmask.
	if identity.Authenticated.ToMask() != 0 || resource.Authenticated.ToMask() != 0 {
		return kernel.ScopeAuthenticated
	}

	// 3. Otherwise, the resource is private to the Account.
	return kernel.ScopeAccount
}

// resolveAuthField merges authenticated permissions from Identity and Resource sources,
// respecting the same governance blocks that apply to public access.
func resolveAuthField(identityVal, resourceVal bool, gov GovernanceOverrides) bool {
	identityAllowed := identityVal && !gov.BlockIdentityBoundPublicAccess
	resourceAllowed := resourceVal && !gov.BlockResourceBoundPublicAccess
	return identityAllowed || resourceAllowed
}
