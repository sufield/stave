package cmdutil

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/domain/policy"
)

// LoadControls creates a control repository and loads controls from dir.
func LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	repo, err := NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	return controls, nil
}

// FindControlByID returns a pointer to the control with the given ID,
// or nil if not found.
func FindControlByID(controls []policy.ControlDefinition, id string) *policy.ControlDefinition {
	for i := range controls {
		if controls[i].ID.String() == id {
			return &controls[i]
		}
	}
	return nil
}
