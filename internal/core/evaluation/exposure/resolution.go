package exposure

import (
	"github.com/sufield/stave/internal/core/kernel"
)

// ResolveAccess computes the final exposure state after applying guardrails.
func ResolveAccess(identity, resource Visibility, gov GovernanceOverrides) ResolvedAccess {
	mask := resolveMask(identity, resource, gov)

	resolved := ResolvedAccess{
		Read:       mask.Has(PermRead),
		Write:      mask.Has(PermWrite),
		List:       mask.Has(PermList),
		Delete:     mask.Has(PermDelete),
		AdminRead:  mask.Has(PermMetadataRead),
		AdminWrite: mask.Has(PermMetadataWrite),
	}

	// Latency: Would this be public if guardrails didn't block it?
	rawPublicRead := identity.Public.Read || resource.Public.Read
	resolved.IsLatent = rawPublicRead && !resolved.Read

	resolved.PrincipalScope = resolvePrincipalScope(identity, resource, mask)

	return resolved
}

// BuildResourceExposure constructs the flattened reachability state used for storage/diagnostics.
func BuildResourceExposure(identity, resource Visibility, gov GovernanceOverrides) ResourceExposure {
	resolved := ResolveAccess(identity, resource, gov)
	return buildExposureFromResolved(identity, resource, gov, resolved)
}

// buildExposureFromResolved constructs a ResourceExposure from pre-computed resolved access.
// This allows callers that already have the ResolvedAccess (e.g. ResolveBucketAccess)
// to avoid a redundant ResolveAccess call.
func buildExposureFromResolved(identity, resource Visibility, gov GovernanceOverrides, resolved ResolvedAccess) ResourceExposure {
	exposure := ResourceExposure{
		// Guardrail Status
		IdentityGuardrailActive: gov.BlockIdentityBoundPublicAccess,
		ResourceGuardrailActive: gov.BlockResourceBoundPublicAccess,

		// Effective Exposure
		PublicRead:   resolved.Read,
		PublicWrite:  resolved.Write,
		PublicList:   resolved.List,
		PublicDelete: resolved.Delete,
		PublicAdmin:  resolved.AdminRead || resolved.AdminWrite,

		// Access Vectors (Identity)
		ReadViaIdentity: identity.Public.Read,
		ListViaIdentity: identity.Public.List,

		// Access Vectors (Resource)
		ReadViaResource:  resource.Public.Read,
		WriteViaResource: resource.Public.Write && !gov.BlockResourceBoundPublicAccess,
		AdminViaResource: resource.Public.Admin && !gov.BlockResourceBoundPublicAccess,

		// Latent Reachability
		LatentPublicRead: resolved.IsLatent,
		LatentPublicList: (identity.Public.List || resource.Public.List) && !resolved.List,
	}

	// Cross-Account / Authenticated Exposure (Post-Guardrails)
	exposure.AuthenticatedRead = resolveAuthField(identity.Authenticated.Read, resource.Authenticated.Read, gov)
	exposure.AuthenticatedWrite = resolveAuthField(identity.Authenticated.Write, resource.Authenticated.Write, gov)
	exposure.AuthenticatedAdmin = resolveAuthField(identity.Authenticated.Admin, resource.Authenticated.Admin, gov)

	return exposure
}

// --- Internal Resolution Logic ---

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
// respecting the same guardrails that apply to public access.
func resolveAuthField(identityVal, resourceVal bool, gov GovernanceOverrides) bool {
	identityAllowed := identityVal && !gov.BlockIdentityBoundPublicAccess
	resourceAllowed := resourceVal && !gov.BlockResourceBoundPublicAccess
	return identityAllowed || resourceAllowed
}
