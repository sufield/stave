package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// ResolveEffectiveVisibility computes effective public visibility accounting for governance overrides.
func ResolveEffectiveVisibility(identity, resource Visibility, gov GovernanceOverrides) EffectiveVisibility {
	effectiveMask := ResolveEffectivePermissions(identity, resource, gov)

	res := EffectiveVisibility{
		Read:     effectiveMask.Has(PermRead),
		Write:    effectiveMask.Has(PermWrite),
		List:     effectiveMask.Has(PermList),
		ACLRead:  effectiveMask.Has(PermACLRead),
		ACLWrite: effectiveMask.Has(PermACLWrite),
		Source:   "None",
	}

	identityReadEffective := !gov.BlockIdentityBoundPublicAccess && identity.Public.Read
	resourceReadEffective := !gov.BlockResourceBoundPublicAccess && resource.Public.Read
	switch {
	case identityReadEffective && resourceReadEffective:
		res.Source = "Combined"
	case identityReadEffective:
		res.Source = "Identity"
	case resourceReadEffective:
		res.Source = "Resource"
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
		PublicReadViaPolicy: in.hasIdentity && in.identity.Public.Read,
		PublicListViaPolicy: in.hasIdentity && in.identity.Public.List,
		PublicReadViaACL:    in.hasResource && in.resource.Public.Read,
	}

	result.PolicyExposureBlocked = in.gov.BlockIdentityBoundPublicAccess
	result.ACLExposureBlocked = in.gov.BlockResourceBoundPublicAccess

	result.PublicRead = effective.Read
	result.PublicWrite = effective.Write
	result.PublicList = effective.List
	result.PublicACLReadable = effective.ACLRead
	result.PublicACLWritable = effective.ACLWrite
	result.PublicWriteViaACL = in.hasResource && !result.ACLExposureBlocked && in.resource.Public.Write

	applyAuthenticatedVisibilityFromIdentity(&result, in)
	applyAuthenticatedVisibilityFromResource(&result, in)

	result.LatentPublicRead = effective.IsLatent
	result.LatentPublicList = result.PublicListViaPolicy && !result.PublicList
	return result
}

func applyAuthenticatedVisibilityFromIdentity(result *VisibilityResult, in visibilityInputs) {
	if !in.hasIdentity || result.PolicyExposureBlocked {
		return
	}
	auth := in.identity.Authenticated
	result.AuthenticatedUsersRead = auth.Read
	result.AuthenticatedUsersWrite = auth.Write
	result.AuthenticatedUsersACLWritable = auth.Admin
	result.AuthenticatedUsersACLReadable = auth.Admin
}

func applyAuthenticatedVisibilityFromResource(result *VisibilityResult, in visibilityInputs) {
	if !in.hasResource || result.ACLExposureBlocked {
		return
	}
	auth := in.resource.Authenticated
	result.AuthenticatedUsersRead = result.AuthenticatedUsersRead || auth.Read
	result.AuthenticatedUsersWrite = result.AuthenticatedUsersWrite || auth.Write
	result.AuthenticatedUsersACLWritable = result.AuthenticatedUsersACLWritable || auth.Admin
	result.AuthenticatedUsersACLReadable = result.AuthenticatedUsersACLReadable || auth.Admin
	result.HasFullControlPublic = in.resource.Public.IsFullControl()
	result.HasFullControlAuthenticatedOnly = in.resource.Authenticated.IsFullControl()
}
