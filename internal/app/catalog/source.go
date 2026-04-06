package catalog

import (
	"context"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// PolicySource defines the interface for retrieving security control
// definitions from various repositories.
type PolicySource interface {
	Fetch(ctx context.Context) ([]policy.ControlDefinition, error)
}

// LibraryProvider is a function type for retrieving the tool's standard
// set of embedded security controls.
type LibraryProvider func() ([]policy.ControlDefinition, error)

// PolicySelector is a function type for retrieving a subset of the
// security library based on specific criteria.
type PolicySelector func(criteria []any) ([]policy.ControlDefinition, error)

// NewLibrarySource creates a policy source that retrieves controls from
// the tool's internal, pre-defined security library.
func NewLibrarySource(provider LibraryProvider) PolicySource {
	return &embeddedLibrary{provider: provider}
}

// NewWorkspaceSource creates a policy source that retrieves custom security
// controls from a local directory or repository.
func NewWorkspaceSource(repo appcontracts.ControlRepository, path string) PolicySource {
	return &localWorkspace{repo: repo, path: path}
}

type embeddedLibrary struct {
	provider LibraryProvider
}

func (s *embeddedLibrary) Fetch(_ context.Context) ([]policy.ControlDefinition, error) {
	return s.provider()
}

type localWorkspace struct {
	repo appcontracts.ControlRepository
	path string
}

func (s *localWorkspace) Fetch(ctx context.Context) ([]policy.ControlDefinition, error) {
	return s.repo.LoadControls(ctx, strings.TrimSpace(s.path))
}
