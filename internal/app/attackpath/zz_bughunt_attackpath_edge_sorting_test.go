package attackpath

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Build_DeterministicEdgeSorting(t *testing.T) {
	// We construct two active chains A and B where:
	// A has postconditions: ["cap_z", "cap_a"]
	// B has preconditions: ["cap_z", "cap_a"]
	// This will generate two edges: from A to B via cap_z, and from A to B via cap_a.
	// Since both edges have FromChain="A" and ToChain="B", their relative order in the sorted slice
	// is non-deterministic under buggy code (which only sorts by FromChain and ToChain).
	// Under correct behavior, we sort by ViaCapability as a tiebreaker, so cap_a must come first.
	chains := []policy.ChainDefinition{
		{
			ID:             kernel.ChainID("A"),
			Postconditions: []string{"cap_z", "cap_a"},
		},
		{
			ID:            kernel.ChainID("B"),
			Preconditions: []string{"cap_z", "cap_a"},
		},
	}

	findings := []ActiveFinding{
		{ChainID: kernel.ChainID("A")},
		{ChainID: kernel.ChainID("B")},
	}

	g := Build(BuildInput{
		Chains:   chains,
		Findings: findings,
	})

	if len(g.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(g.Edges))
	}

	// Under buggy code, the order of edges could match the loop traversal order: "cap_z" first, then "cap_a".
	// We assert that the edges are sorted alphabetically by ViaCapability: "cap_a" first.
	if g.Edges[0].ViaCapability != CapabilityID("cap_a") {
		t.Errorf("expected Edge 0 to have ViaCapability='cap_a', got %q", g.Edges[0].ViaCapability)
	}
	if g.Edges[1].ViaCapability != CapabilityID("cap_z") {
		t.Errorf("expected Edge 1 to have ViaCapability='cap_z', got %q", g.Edges[1].ViaCapability)
	}
}
