package catalog

import (
	"context"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestNewBuiltInProvider_Load(t *testing.T) {
	allFn := func() ([]policy.ControlDefinition, error) {
		return []policy.ControlDefinition{
			{ID: "CTL.A.001"},
			{ID: "CTL.B.001"},
		}, nil
	}

	provider := NewBuiltInProvider(allFn)
	controls, err := provider.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(controls) != 2 {
		t.Fatalf("expected 2, got %d", len(controls))
	}
}
