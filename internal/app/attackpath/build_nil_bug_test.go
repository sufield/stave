package attackpath

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuild_NilControlPointerInMapHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Build panicked on nil control definition in lookup map: %v", rec)
		}
	}()

	in := BuildInput{
		Chains: []policy.ChainDefinition{
			{
				ID:         kernel.ChainID("CHAIN_01"),
				ControlIDs: []kernel.ControlID{"CTL.S3.001"},
			},
		},
		ControlLookup: map[string]*policy.ControlDefinition{
			"CTL.S3.001": nil, // nil pointer in lookup map
		},
	}

	graph := Build(in)
	if graph == nil {
		t.Fatalf("expected non-nil attackpath Graph")
	}

	if len(graph.ChainNodes) != 1 {
		t.Errorf("expected 1 chain node, got %d", len(graph.ChainNodes))
	}
}
