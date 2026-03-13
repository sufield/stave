package compose

import (
	"context"
	"errors"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/policy"
)

// ErrControlNotFound is returned when a control ID is not found in the loaded set.
var ErrControlNotFound = errors.New("control not found")

// ControlLoader wraps the logic for retrieving policy definitions.
// Using a struct allows for easier testing and potential caching.
type ControlLoader struct {
	repo appcontracts.ControlRepository
}

// NewLoader initializes a loader with the default repository.
func NewLoader() (*ControlLoader, error) {
	repo, err := NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("initializing control repository: %w", err)
	}
	return &ControlLoader{repo: repo}, nil
}

// LoadControls retrieves all control definitions from the specified directory.
func (l *ControlLoader) LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	controls, err := l.repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading controls from %s: %w", dir, err)
	}
	return controls, nil
}

// LoadMappedControls loads controls and returns them as a map keyed by ID.
// This is useful for CLI tools that need to perform multiple lookups.
func (l *ControlLoader) LoadMappedControls(ctx context.Context, dir string) (map[string]policy.ControlDefinition, error) {
	controls, err := l.LoadControls(ctx, dir)
	if err != nil {
		return nil, err
	}

	m := make(map[string]policy.ControlDefinition, len(controls))
	for _, c := range controls {
		m[c.ID.String()] = c
	}
	return m, nil
}

// --- Package Level Helpers (Functional API) ---

// LoadControls is a convenience wrapper for one-off loading.
func LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	l, err := NewLoader()
	if err != nil {
		return nil, err
	}
	return l.LoadControls(ctx, dir)
}

// LoadControlByID retrieves a single control by its ID.
// Note: If calling this multiple times, prefer using LoadMappedControls for efficiency.
func LoadControlByID(ctx context.Context, dir, id string) (policy.ControlDefinition, error) {
	controls, err := LoadControls(ctx, dir)
	if err != nil {
		return policy.ControlDefinition{}, err
	}

	for _, c := range controls {
		if c.ID.String() == id {
			return c, nil
		}
	}

	return policy.ControlDefinition{}, fmt.Errorf("%w: %q in %s", ErrControlNotFound, id, dir)
}

// FindControlByID searches a slice for a specific ID.
// Returns (value, true) if found, (zero, false) otherwise.
// This avoids returning nil pointers to stack/slice variables.
func FindControlByID(controls []policy.ControlDefinition, id string) (policy.ControlDefinition, bool) {
	for _, c := range controls {
		if c.ID.String() == id {
			return c, true
		}
	}
	return policy.ControlDefinition{}, false
}
