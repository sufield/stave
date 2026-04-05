package exposure

import "testing"

func TestResolveAccess_PolicyBlockedLatentRead(t *testing.T) {
	got := ResolveAccess(
		Visibility{Public: Capabilities{Read: true}},
		Visibility{},
		GovernanceOverrides{BlockIdentityBoundPublicAccess: true},
	)

	if got.Read {
		t.Fatal("expected Read=false when policy is blocked by governance override")
	}
	if !got.IsLatent {
		t.Fatal("expected IsLatent=true when public read would exist without governance override")
	}
}

func TestResolveAccess_UnionAcrossIdentityAndResource(t *testing.T) {
	got := ResolveAccess(
		Visibility{Public: Capabilities{List: true}},
		Visibility{Public: Capabilities{Read: true}},
		GovernanceOverrides{},
	)

	if !got.Read {
		t.Fatal("expected Read=true from resource")
	}
	if !got.List {
		t.Fatal("expected List=true from identity")
	}
}

func TestResolveAccess_DeleteAndAdmin(t *testing.T) {
	got := ResolveAccess(
		Visibility{Public: Capabilities{Delete: true, Admin: true}},
		Visibility{},
		GovernanceOverrides{},
	)

	if !got.Delete {
		t.Fatal("expected Delete=true")
	}
	if !got.AdminRead {
		t.Fatal("expected AdminRead=true")
	}
	if !got.AdminWrite {
		t.Fatal("expected AdminWrite=true")
	}
}
