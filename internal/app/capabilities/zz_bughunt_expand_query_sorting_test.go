package capabilities_test

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/app/capabilities"
)

func TestBugHunt_ExpandQuery_DeterministicSorting(t *testing.T) {
	// Under buggy code, ExpandQuery returns terms in a non-deterministic order
	// because it iterates over a Go map.
	// We assert that the returned slice is sorted alphabetically.
	tokens := []string{"role", "public"}
	expanded1 := capabilities.ExpandQuery(tokens)

	// Expected sorted order:
	// "role" synonyms: "iam", "identity"
	// "public" synonyms: "open", "internet", "anonymous", "unauthenticated", "world", "allusers", "everyone"
	// Total unique tokens: "role", "iam", "identity", "public", "open", "internet", "anonymous", "unauthenticated", "world", "allusers", "everyone"
	// Alphabetical sorted list:
	// "allusers", "anonymous", "everyone", "iam", "identity", "internet", "open", "public", "role", "unauthenticated", "world"
	expected := []string{
		"allusers", "anonymous", "everyone", "iam", "identity",
		"internet", "open", "public", "role", "unauthenticated", "world",
	}

	if len(expanded1) != len(expected) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expected), len(expanded1), expanded1)
	}

	if !reflect.DeepEqual(expanded1, expected) {
		t.Errorf("expected sorted list %v, got %v", expected, expanded1)
	}
}
