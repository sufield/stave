package yaml

import (
	"context"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// ChainProvider implements appcontracts.ChainDefinitionLoader by delegating
// to the package-level LoadChains function. The struct exists so callers
// can inject a port interface rather than a free function.
type ChainProvider struct{}

// NewChainProvider returns the standard chain definition loader.
func NewChainProvider() *ChainProvider { return &ChainProvider{} }

var _ appcontracts.ChainDefinitionLoader = (*ChainProvider)(nil)

// LoadChains reads chain definitions from dir, validating against the
// supplied capability registry (nil registry skips capability validation).
// The ctx parameter is accepted for interface conformance — the underlying
// disk read is not yet cancellation-aware.
func (ChainProvider) LoadChains(_ context.Context, dir string, registry policy.CapabilityRegistry) ([]policy.ChainDefinition, error) {
	return LoadChains(dir, registry)
}
