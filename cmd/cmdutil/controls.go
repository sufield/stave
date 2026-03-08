package cmdutil

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/domain/policy"
)

// ErrControlNotFound is returned when a control ID is not found in the loaded set.
var ErrControlNotFound = errors.New("control not found")

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

// LoadControlByID loads all controls from dir and returns the one matching id.
// Returns ErrControlNotFound (wrapped) if no control with that ID exists.
func LoadControlByID(ctx context.Context, dir, id string) (*policy.ControlDefinition, error) {
	controls, err := LoadControls(ctx, dir)
	if err != nil {
		return nil, err
	}
	if ctl := FindControlByID(controls, id); ctl != nil {
		return ctl, nil
	}
	return nil, fmt.Errorf("%w: %q in %s", ErrControlNotFound, id, dir)
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
