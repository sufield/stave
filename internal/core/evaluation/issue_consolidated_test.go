package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestIsConsolidated_SingleMember(t *testing.T) {
	iss := Issue{MemberFindingIDs: []kernel.FindingID{"f1"}}
	if iss.IsConsolidated() {
		t.Error("single-member issue should not be consolidated")
	}
}

func TestIsConsolidated_MultipleMembers(t *testing.T) {
	iss := Issue{MemberFindingIDs: []kernel.FindingID{"f1", "f2"}}
	if !iss.IsConsolidated() {
		t.Error("multi-member issue should be consolidated")
	}
}

func TestIsConsolidated_Empty(t *testing.T) {
	iss := Issue{}
	if iss.IsConsolidated() {
		t.Error("empty issue should not be consolidated")
	}
}

func TestParentNamespace(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"storage.access.public_read", "storage.access"},
		{"storage.access", ""},
		{"storage", ""},
		{"a.b.c.d", "a.b.c"},
	}
	for _, tc := range tests {
		got := parentNamespace(tc.key)
		if got != tc.want {
			t.Errorf("parentNamespace(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestRootCauseKeys_ExcludesDiscriminators(t *testing.T) {
	trace := []MatchedClause{
		{ObservationKey: "storage.kind"},
		{ObservationKey: "storage.access.public_read"},
	}
	keys := rootCauseKeys(trace)
	if _, ok := keys["storage.kind"]; ok {
		t.Error("discriminator key should be excluded")
	}
	if _, ok := keys["storage.access.public_read"]; !ok {
		t.Error("non-discriminator key should be included")
	}
	if _, ok := keys["storage.access"]; !ok {
		t.Error("parent namespace should be included")
	}
}
