package exposure

import "testing"

func TestResolveEffectiveVisibility_PolicyBlockedLatentRead(t *testing.T) {
	got := ResolveEffectiveVisibility(
		PolicyAnalysis{AccessFlags: AccessFlags{AllowsPublicRead: true}},
		ACLAnalysis{},
		PublicAccessBlock{BlockPublicPolicy: true},
	)

	if got.Read {
		t.Fatal("expected Read=false when policy is blocked by PAB")
	}
	if !got.IsLatent {
		t.Fatal("expected IsLatent=true when public read would exist without PAB")
	}
}

func TestResolveEffectiveVisibility_UnionAcrossPolicyAndACL(t *testing.T) {
	got := ResolveEffectiveVisibility(
		PolicyAnalysis{AllowsPublicList: true},
		ACLAnalysis{AccessFlags: AccessFlags{AllowsPublicRead: true}},
		PublicAccessBlock{},
	)

	if !got.Read {
		t.Fatal("expected Read=true from ACL")
	}
	if !got.List {
		t.Fatal("expected List=true from policy")
	}
	if got.Source != "ACL" {
		t.Fatalf("expected Source=ACL for effective public read, got %q", got.Source)
	}
}
