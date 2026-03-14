package exposure

import "testing"

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
			ExternalAccountARNs: []string{"arn:aws:iam::123456789012:root"},
		},
		NetworkScope: NetworkScopeAccess{
			HasIPCondition:        true,
			EffectiveNetworkScope: "ip-restricted",
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
