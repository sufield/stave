package exposure

import "testing"

func TestResolveEffectiveVisibility_PolicyBlockedLatentRead(t *testing.T) {
	got := ResolveEffectiveVisibility(
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

func TestResolveEffectiveVisibility_UnionAcrossIdentityAndResource(t *testing.T) {
	got := ResolveEffectiveVisibility(
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

func TestResolveEffectiveVisibility_DeleteAndAdmin(t *testing.T) {
	got := ResolveEffectiveVisibility(
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
	if !got.IsExposed() {
		t.Fatal("expected IsExposed=true")
	}
}
