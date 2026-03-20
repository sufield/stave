package compose

import (
	"context"
	"errors"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// ErrControlNotFound is returned when a control ID is not found in the loaded set.
var ErrControlNotFound = errors.New("control not found")

// ControlLoader wraps the logic for retrieving policy definitions.
// Using a struct allows for easier testing and potential caching.
type ControlLoader struct {
	repo appcontracts.ControlRepository
}

// NewLoader initializes a loader with the given provider's repository.
func NewLoader(p *Provider) (*ControlLoader, error) {
	repo, err := p.NewControlRepo()
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

// --- Package Level Helpers (Functional API) ---

// LoadControls is a convenience wrapper for one-off loading.
func LoadControls(ctx context.Context, p *Provider, dir string) ([]policy.ControlDefinition, error) {
	l, err := NewLoader(p)
	if err != nil {
		return nil, err
	}
	return l.LoadControls(ctx, dir)
}

// LoadControlByID retrieves a single control by its ID.
// Note: If calling this multiple times, prefer using LoadMappedControls for efficiency.
func LoadControlByID(ctx context.Context, p *Provider, dir, id string) (policy.ControlDefinition, error) {
	controls, err := LoadControls(ctx, p, dir)
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
