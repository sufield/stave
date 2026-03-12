package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// ResolveEffectiveVisibility computes effective public visibility accounting for governance overrides.
func ResolveEffectiveVisibility(identity, resource Visibility, gov GovernanceOverrides) EffectiveVisibility {
	effectiveMask := ResolveEffectivePermissions(identity, resource, gov)

	res := EffectiveVisibility{
		Read:       effectiveMask.Has(PermRead),
		Write:      effectiveMask.Has(PermWrite),
		List:       effectiveMask.Has(PermList),
		Delete:     effectiveMask.Has(PermDelete),
		AdminRead:  effectiveMask.Has(PermMetadataRead),
		AdminWrite: effectiveMask.Has(PermMetadataWrite),
	}

	res.IsLatent = (identity.Public.Read || resource.Public.Read) && !res.Read
	res.PrincipalScope = resolvePrincipalScope(identity, resource, effectiveMask)

	return res
}

func resolvePrincipalScope(identity, resource Visibility, effectiveMask Permission) kernel.PrincipalScope {
	if effectiveMask != 0 {
		return kernel.ScopePublic
	}
	if hasAuthenticatedAccess(identity, resource) {
		return kernel.ScopeAuthenticated
	}
	return kernel.ScopeAccount
}

func hasAuthenticatedAccess(identity, resource Visibility) bool {
	return identity.Authenticated.ToMask() != 0 || resource.Authenticated.ToMask() != 0
}

type visibilityInputs struct {
	hasIdentity bool
	identity    Visibility
	hasResource bool
	resource    Visibility
	gov         GovernanceOverrides
}

// BuildVisibilityResult constructs a full VisibilityResult from analysis inputs.
func BuildVisibilityResult(hasIdentity bool, identity Visibility, hasResource bool, resource Visibility, gov GovernanceOverrides) VisibilityResult {
	return newVisibilityResult(visibilityInputs{
		hasIdentity: hasIdentity,
		identity:    identity,
		hasResource: hasResource,
		resource:    resource,
		gov:         gov,
	})
}

func newVisibilityResult(in visibilityInputs) VisibilityResult {
	effective := ResolveEffectiveVisibility(in.identity, in.resource, in.gov)
	result := VisibilityResult{
		ReadViaIdentity: in.hasIdentity && in.identity.Public.Read,
		ListViaIdentity: in.hasIdentity && in.identity.Public.List,
		ReadViaResource: in.hasResource && in.resource.Public.Read,
	}

	result.IdentityExposureBlocked = in.gov.BlockIdentityBoundPublicAccess
	result.ResourceExposureBlocked = in.gov.BlockResourceBoundPublicAccess

	result.PublicRead = effective.Read
	result.PublicWrite = effective.Write
	result.PublicList = effective.List
	result.PublicDelete = effective.Delete
	result.PublicAdmin = effective.AdminRead || effective.AdminWrite
	result.WriteViaResource = in.hasResource && !result.ResourceExposureBlocked && in.resource.Public.Write
	result.AdminViaResource = in.hasResource && !result.ResourceExposureBlocked && in.resource.Public.Admin

	applyAuthenticatedVisibilityFromIdentity(&result, in)
	applyAuthenticatedVisibilityFromResource(&result, in)

	result.LatentPublicRead = effective.IsLatent
	result.LatentPublicList = result.ListViaIdentity && !result.PublicList
	return result
}

func applyAuthenticatedVisibilityFromIdentity(result *VisibilityResult, in visibilityInputs) {
	if !in.hasIdentity || result.IdentityExposureBlocked {
		return
	}
	auth := in.identity.Authenticated
	result.AuthenticatedRead = auth.Read
	result.AuthenticatedWrite = auth.Write
	result.AuthenticatedAdmin = auth.Admin
}

func applyAuthenticatedVisibilityFromResource(result *VisibilityResult, in visibilityInputs) {
	if !in.hasResource || result.ResourceExposureBlocked {
		return
	}
	auth := in.resource.Authenticated
	result.AuthenticatedRead = result.AuthenticatedRead || auth.Read
	result.AuthenticatedWrite = result.AuthenticatedWrite || auth.Write
	result.AuthenticatedAdmin = result.AuthenticatedAdmin || auth.Admin
}
