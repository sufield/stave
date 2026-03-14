package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// CrossAccountAccess captures cross-account and external principal facts.
type CrossAccountAccess struct {
	ExternalAccountARNs []string
	ExternalAccountIDs  []string
	HasExternalAccess   bool
	HasExternalWrite    bool
}

// NetworkScopeAccess captures network-level policy conditions.
type NetworkScopeAccess struct {
	HasIPCondition        bool
	HasVPCCondition       bool
	EffectiveNetworkScope string
}

// ACLFullControlAccess captures full-control ACL grants.
type ACLFullControlAccess struct {
	FullControlPublic        bool
	FullControlAuthenticated bool
}

// PrefixExposureAccess captures prefix-level read exposure evidence.
type PrefixExposureAccess struct {
	HasIdentityEvidence   bool
	HasResourceEvidence   bool
	IdentityReadScopes    []kernel.ObjectPrefix
	IdentitySourceByScope map[kernel.ObjectPrefix]kernel.StatementID
	IdentityReadBlocked   bool
	ResourceReadAll       bool
	ResourceReadBlocked   bool
}

// BucketAccess is the domain aggregate that owns all access computation
// for a single bucket. Both the extractor and snapshot paths converge here.
type BucketAccess struct {
	Visibility        VisibilityResult
	Governance        GovernanceOverrides
	CrossAccount      CrossAccountAccess
	NetworkScope      NetworkScopeAccess
	ACLFullControl    ACLFullControlAccess
	PrefixExposure    PrefixExposureAccess
	HasWildcardPolicy bool
	Scope             kernel.PrincipalScope
	TrustBoundary     kernel.TrustBoundary
}

// BucketAccessInput carries the raw signals needed to resolve a BucketAccess.
type BucketAccessInput struct {
	Identity          Visibility
	Resource          Visibility
	Gov               GovernanceOverrides
	CrossAccount      CrossAccountAccess
	NetworkScope      NetworkScopeAccess
	ACLFullControl    ACLFullControlAccess
	PrefixExposure    PrefixExposureAccess
	HasWildcardPolicy bool
}

// ResolveBucketAccess computes the full BucketAccess aggregate from raw inputs.
// It resolves effective visibility once and uses it for both the VisibilityResult
// projection and the computed Scope/TrustBoundary fields.
func ResolveBucketAccess(in BucketAccessInput) BucketAccess {
	effective := ResolveEffectiveVisibility(in.Identity, in.Resource, in.Gov)
	return BucketAccess{
		Visibility:        buildVisibilityFromEffective(in.Identity, in.Resource, in.Gov, effective),
		Governance:        in.Gov,
		CrossAccount:      in.CrossAccount,
		NetworkScope:      in.NetworkScope,
		ACLFullControl:    in.ACLFullControl,
		PrefixExposure:    in.PrefixExposure,
		HasWildcardPolicy: in.HasWildcardPolicy,
		Scope:             effective.PrincipalScope,
		TrustBoundary:     resolveTrustBoundary(effective.PrincipalScope, in.CrossAccount),
	}
}

func resolveTrustBoundary(scope kernel.PrincipalScope, ca CrossAccountAccess) kernel.TrustBoundary {
	switch {
	case scope == kernel.ScopePublic || scope == kernel.ScopeAuthenticated:
		return kernel.BoundaryExternal
	case ca.HasExternalAccess:
		return kernel.BoundaryCrossAccount
	default:
		return kernel.BoundaryInternal
	}
}
