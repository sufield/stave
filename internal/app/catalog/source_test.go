package catalog

import (
	"context"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestNewLibrarySource_Fetch(t *testing.T) {
	provider := func() ([]policy.ControlDefinition, error) {
		return []policy.ControlDefinition{
			{ID: "CTL.A.001"},
			{ID: "CTL.B.001"},
		}, nil
	}

	source := NewLibrarySource(provider)
	controls, err := source.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(controls) != 2 {
		t.Fatalf("expected 2, got %d", len(controls))
	}
}
