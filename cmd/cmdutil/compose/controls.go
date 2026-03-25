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

// LoadControls retrieves all control definitions from the specified directory.
func (l *ControlLoader) LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	controls, err := l.repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading controls from %s: %w", dir, err)
	}
	return controls, nil
}

// --- Package Level Helpers (Functional API) ---

// LoadControls is a convenience wrapper for one-off loading via Provider.
func LoadControls(ctx context.Context, p *Provider, dir string) ([]policy.ControlDefinition, error) {
	return LoadControlsFrom(ctx, p.NewControlRepo, dir)
}

// LoadControlsFrom loads controls using an explicit factory function.
func LoadControlsFrom(ctx context.Context, newCtlRepo CtlRepoFactory, dir string) ([]policy.ControlDefinition, error) {
	repo, err := newCtlRepo()
	if err != nil {
		return nil, fmt.Errorf("initializing control repository: %w", err)
	}
	l := &ControlLoader{repo: repo}
	return l.LoadControls(ctx, dir)
}
