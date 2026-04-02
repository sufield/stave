package exposure

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestResolveBucketAccess_VisibilityMatchesDirect(t *testing.T) {
	identity := Visibility{
		Public: Capabilities{Read: true, List: true},
	}
	resource := Visibility{
		Public: Capabilities{Write: true, Admin: true},
	}
	gov := GovernanceOverrides{
		BlockIdentityBoundPublicAccess: true,
	}

	direct := BuildVisibilityResult(identity, resource, gov)
	access := ResolveBucketAccess(BucketAccessInput{
		Identity: identity,
		Resource: resource,
		Gov:      gov,
	})

	if access.Visibility != direct {
		t.Errorf("Visibility mismatch:\n  ResolveBucketAccess: %+v\n  BuildVisibilityResult: %+v", access.Visibility, direct)
	}
}

func TestResolveBucketAccess_PassthroughFields(t *testing.T) {
	in := BucketAccessInput{
		CrossAccount: CrossAccountAccess{
			HasExternalAccess:   true,
			ExternalAccountARNs: []kernel.AWSAccountARN{"arn:aws:iam::123456789012:root"},
		},
		NetworkScope: NetworkScopeAccess{
			HasIPCondition:        true,
			EffectiveNetworkScope: kernel.NetworkScopeIPRestricted,
		},
		ACLFullControl: ACLFullControlAccess{
			FullControlPublic: true,
		},
		HasWildcardPolicy: true,
		Gov: GovernanceOverrides{
			BlockResourceBoundPublicAccess: true,
		},
	}

	access := ResolveBucketAccess(in)

	if !access.CrossAccount.HasExternalAccess {
		t.Error("expected CrossAccount.HasExternalAccess")
	}
	if !access.NetworkScope.HasIPCondition {
		t.Error("expected NetworkScope.HasIPCondition")
	}
	if !access.ACLFullControl.FullControlPublic {
		t.Error("expected ACLFullControl.FullControlPublic")
	}
	if !access.HasWildcardPolicy {
		t.Error("expected HasWildcardPolicy")
	}
	if !access.Governance.BlockResourceBoundPublicAccess {
		t.Error("expected Governance passthrough")
	}
}

func TestResolveBucketAccess_ScopeAndTrustBoundary(t *testing.T) {
	tests := []struct {
		name         string
		in           BucketAccessInput
		wantScope    kernel.PrincipalScope
		wantBoundary kernel.TrustBoundary
	}{
		{
			name: "public read → ScopePublic, BoundaryExternal",
			in: BucketAccessInput{
				Resource: Visibility{Public: Capabilities{Read: true}},
			},
			wantScope:    kernel.ScopePublic,
			wantBoundary: kernel.BoundaryExternal,
		},
		{
			name: "authenticated read → ScopeAuthenticated, BoundaryExternal",
			in: BucketAccessInput{
				Resource: Visibility{Authenticated: Capabilities{Read: true}},
			},
			wantScope:    kernel.ScopeAuthenticated,
			wantBoundary: kernel.BoundaryExternal,
		},
		{
			name: "cross-account access → ScopeAccount, BoundaryCrossAccount",
			in: BucketAccessInput{
				CrossAccount: CrossAccountAccess{HasExternalAccess: true},
			},
			wantScope:    kernel.ScopeAccount,
			wantBoundary: kernel.BoundaryCrossAccount,
		},
		{
			name:         "account-only → ScopeAccount, BoundaryInternal",
			in:           BucketAccessInput{},
			wantScope:    kernel.ScopeAccount,
			wantBoundary: kernel.BoundaryInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			access := ResolveBucketAccess(tt.in)
			if access.Scope != tt.wantScope {
				t.Errorf("Scope = %v, want %v", access.Scope, tt.wantScope)
			}
			if access.TrustBoundary != tt.wantBoundary {
				t.Errorf("TrustBoundary = %v, want %v", access.TrustBoundary, tt.wantBoundary)
			}
		})
	}
}
