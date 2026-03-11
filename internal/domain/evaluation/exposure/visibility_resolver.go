package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// ResolveEffectiveVisibility computes effective public visibility accounting for PAB.
func ResolveEffectiveVisibility(policy PolicyAnalysis, acl ACLAnalysis, pab PublicAccessBlock) EffectiveVisibility {
	policyMask := policy.ToPublicMask()
	aclMask := acl.ToPublicMask()
	effectiveMask, policyBlocked, aclBlocked := pab.ResolveEffectivePermissions(policyMask, aclMask)

	res := EffectiveVisibility{
		Read:     effectiveMask.Has(PermRead),
		Write:    effectiveMask.Has(PermWrite),
		List:     effectiveMask.Has(PermList),
		ACLRead:  effectiveMask.Has(PermACLRead),
		ACLWrite: effectiveMask.Has(PermACLWrite),
		Source:   "None",
	}

	policyReadEffective := !policyBlocked && policy.PublicRead
	aclReadEffective := !aclBlocked && acl.PublicRead
	switch {
	case policyReadEffective && aclReadEffective:
		res.Source = "Combined"
	case policyReadEffective:
		res.Source = "Policy"
	case aclReadEffective:
		res.Source = "ACL"
	}

	res.IsLatent = (policy.PublicRead || acl.PublicRead) && !res.Read
	res.PrincipalScope = resolvePrincipalScope(policy, acl, effectiveMask)

	return res
}

func resolvePrincipalScope(policy PolicyAnalysis, acl ACLAnalysis, effectiveMask Permission) kernel.PrincipalScope {
	if effectiveMask != 0 {
		return kernel.ScopePublic
	}
	if hasAuthenticatedPrincipalAccess(policy, acl) {
		return kernel.ScopeAuthenticated
	}
	return kernel.ScopeAccount
}

func hasAuthenticatedPrincipalAccess(policy PolicyAnalysis, acl ACLAnalysis) bool {
	return policy.AuthenticatedRead ||
		policy.AuthenticatedList ||
		policy.AuthenticatedWrite ||
		policy.AuthenticatedACLRead ||
		policy.AuthenticatedACLWrite ||
		acl.AuthenticatedRead ||
		acl.AuthenticatedWrite ||
		acl.AuthenticatedACLRead ||
		acl.AuthenticatedACLWrite ||
		acl.AuthenticatedFullControl
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
		PublicReadViaPolicy: in.hasPolicy && in.policy.PublicRead,
		PublicListViaPolicy: in.hasPolicy && in.policy.PublicList,
		PublicReadViaACL:    in.hasACL && in.acl.PublicRead,
	}

	result.PolicyExposureBlocked = in.pab.BlockPublicPolicy || in.pab.RestrictPublicBuckets
	result.ACLExposureBlocked = in.pab.BlockPublicACLs || in.pab.IgnorePublicACLs

	result.PublicRead = effective.Read
	result.PublicWrite = effective.Write
	result.PublicList = effective.List
	result.PublicACLReadable = effective.ACLRead
	result.PublicACLWritable = effective.ACLWrite
	result.PublicWriteViaACL = in.hasACL && !result.ACLExposureBlocked && in.acl.PublicWrite

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
	result.AuthenticatedUsersRead = in.policy.AuthenticatedRead
	result.AuthenticatedUsersWrite = in.policy.AuthenticatedWrite
	result.AuthenticatedUsersACLWritable = in.policy.AuthenticatedACLWrite
	result.AuthenticatedUsersACLReadable = in.policy.AuthenticatedACLRead
}

func applyAuthenticatedVisibilityFromACL(result *VisibilityResult, in visibilityInputs) {
	if !in.hasACL || result.ACLExposureBlocked {
		return
	}
	result.AuthenticatedUsersRead = result.AuthenticatedUsersRead || in.acl.AuthenticatedRead
	result.AuthenticatedUsersWrite = result.AuthenticatedUsersWrite || in.acl.AuthenticatedWrite
	result.AuthenticatedUsersACLWritable = result.AuthenticatedUsersACLWritable || in.acl.AuthenticatedACLWrite
	result.AuthenticatedUsersACLReadable = result.AuthenticatedUsersACLReadable || in.acl.AuthenticatedACLRead
	result.HasFullControlPublic = in.acl.PublicFullControl
	result.HasFullControlAuthenticatedOnly = in.acl.AuthenticatedFullControl
}
