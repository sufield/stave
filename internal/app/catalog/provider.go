package catalog

import (
	"context"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// ControlProvider loads controls from any source.
type ControlProvider interface {
	Load(ctx context.Context) ([]policy.ControlDefinition, error)
}

// BuiltInLoader loads all built-in controls. Satisfied by builtin.Registry.All.
type BuiltInLoader func() ([]policy.ControlDefinition, error)

// FilteredLoader loads built-in controls matching selectors. Satisfied by builtin.Registry.Filtered.
type FilteredLoader func(selectors []any) ([]policy.ControlDefinition, error)

// NewBuiltInProvider creates a provider that loads from embedded controls.
// allFn and filteredFn are injected from the adapter layer to avoid
// importing adapters in the app layer.
func NewBuiltInProvider(allFn BuiltInLoader) ControlProvider {
	return &builtInProvider{allFn: allFn}
}

// NewFSProvider creates a provider that loads from the filesystem.
func NewFSProvider(repo appcontracts.ControlRepository, dir string) ControlProvider {
	return &fsProvider{repo: repo, dir: dir}
}

type builtInProvider struct {
	allFn BuiltInLoader
}

func (p *builtInProvider) Load(_ context.Context) ([]policy.ControlDefinition, error) {
	return p.allFn()
}

type fsProvider struct {
	repo appcontracts.ControlRepository
	dir  string
}

func (p *fsProvider) Load(ctx context.Context) ([]policy.ControlDefinition, error) {
	return p.repo.LoadControls(ctx, strings.TrimSpace(p.dir))
}
