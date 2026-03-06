package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// ResolveEffectiveVisibility computes effective public visibility accounting for PAB.
func ResolveEffectiveVisibility(policy PolicyAnalysis, acl ACLAnalysis, pab PublicAccessBlock) EffectiveVisibility {
	policyMask := policyPublicMask(policy)
	aclMask := aclPublicMask(acl)
	effectiveMask, policyBlocked, aclBlocked := applyPublicAccessBlock(policyMask, aclMask, pab)

	res := EffectiveVisibility{
		Read:     effectiveMask.has(accessPermRead),
		Write:    effectiveMask.has(accessPermWrite),
		List:     effectiveMask.has(accessPermList),
		ACLRead:  effectiveMask.has(accessPermACLRead),
		ACLWrite: effectiveMask.has(accessPermACLWrite),
		Source:   "None",
	}

	policyReadEffective := !policyBlocked && policy.AllowsPublicRead
	aclReadEffective := !aclBlocked && acl.AllowsPublicRead
	switch {
	case policyReadEffective && aclReadEffective:
		res.Source = "Combined"
	case policyReadEffective:
		res.Source = "Policy"
	case aclReadEffective:
		res.Source = "ACL"
	}

	res.IsLatent = (policy.AllowsPublicRead || acl.AllowsPublicRead) && !res.Read
	res.PrincipalScope = resolvePrincipalScope(policy, acl, effectiveMask)

	return res
}

func resolvePrincipalScope(policy PolicyAnalysis, acl ACLAnalysis, effectiveMask accessPermissionMask) kernel.PrincipalScope {
	if effectiveMask != 0 {
		return kernel.ScopePublic
	}
	if hasAuthenticatedPrincipalAccess(policy, acl) {
		return kernel.ScopeAuthenticated
	}
	return kernel.ScopeAccount
}

func hasAuthenticatedPrincipalAccess(policy PolicyAnalysis, acl ACLAnalysis) bool {
	return policy.AllowsAuthenticatedRead ||
		policy.AllowsAuthenticatedList ||
		policy.AllowsAuthenticatedWrite ||
		policy.AllowsAuthenticatedACLRead ||
		policy.AllowsAuthenticatedACLWrite ||
		acl.AllowsAuthenticatedRead ||
		acl.AllowsAuthenticatedWrite ||
		acl.AllowsAuthenticatedACLRead ||
		acl.AllowsAuthenticatedACLWrite ||
		acl.HasFullControlAuthenticated
}

type visibilityInputs struct {
	hasPolicy bool
	policy    PolicyAnalysis
	hasACL    bool
	acl       ACLAnalysis
	pab       PublicAccessBlock
}

// BuildVisibilityResult constructs a full VisibilityResult from analysis inputs.
func BuildVisibilityResult(hasPolicy bool, policy PolicyAnalysis, hasACL bool, acl ACLAnalysis, pab PublicAccessBlock) VisibilityResult {
	return newVisibilityResult(visibilityInputs{
		hasPolicy: hasPolicy,
		policy:    policy,
		hasACL:    hasACL,
		acl:       acl,
		pab:       pab,
	})
}

func newVisibilityResult(in visibilityInputs) VisibilityResult {
	effective := ResolveEffectiveVisibility(in.policy, in.acl, in.pab)
	result := VisibilityResult{
		PublicReadViaPolicy: in.hasPolicy && in.policy.AllowsPublicRead,
		PublicListViaPolicy: in.hasPolicy && in.policy.AllowsPublicList,
		PublicReadViaACL:    in.hasACL && in.acl.AllowsPublicRead,
	}

	result.PolicyExposureBlocked = in.pab.BlockPublicPolicy || in.pab.RestrictPublicBuckets
	result.ACLExposureBlocked = in.pab.BlockPublicAcls || in.pab.IgnorePublicAcls

	result.PublicRead = effective.Read
	result.PublicWrite = effective.Write
	result.PublicList = effective.List
	result.PublicACLReadable = effective.ACLRead
	result.PublicACLWritable = effective.ACLWrite
	result.PublicWriteViaACL = in.hasACL && !result.ACLExposureBlocked && in.acl.AllowsPublicWrite

	applyAuthenticatedVisibilityFromPolicy(&result, in)
	applyAuthenticatedVisibilityFromACL(&result, in)

	result.LatentPublicRead = effective.IsLatent
	result.LatentPublicList = result.PublicListViaPolicy && !result.PublicList
	return result
}

func applyAuthenticatedVisibilityFromPolicy(result *VisibilityResult, in visibilityInputs) {
	if !in.hasPolicy || result.PolicyExposureBlocked {
		return
	}
	result.AuthenticatedUsersRead = in.policy.AllowsAuthenticatedRead
	result.AuthenticatedUsersWrite = in.policy.AllowsAuthenticatedWrite
	result.AuthenticatedUsersACLWritable = in.policy.AllowsAuthenticatedACLWrite
	result.AuthenticatedUsersACLReadable = in.policy.AllowsAuthenticatedACLRead
}

func applyAuthenticatedVisibilityFromACL(result *VisibilityResult, in visibilityInputs) {
	if !in.hasACL || result.ACLExposureBlocked {
		return
	}
	result.AuthenticatedUsersRead = result.AuthenticatedUsersRead || in.acl.AllowsAuthenticatedRead
	result.AuthenticatedUsersWrite = result.AuthenticatedUsersWrite || in.acl.AllowsAuthenticatedWrite
	result.AuthenticatedUsersACLWritable = result.AuthenticatedUsersACLWritable || in.acl.AllowsAuthenticatedACLWrite
	result.AuthenticatedUsersACLReadable = result.AuthenticatedUsersACLReadable || in.acl.AllowsAuthenticatedACLRead
	result.HasFullControlPublic = in.acl.HasFullControlPublic
	result.HasFullControlAuthenticatedOnly = in.acl.HasFullControlAuthenticated
}
