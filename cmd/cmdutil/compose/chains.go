package compose

import (
	"context"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/builtin/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// LoadChainDefinitions resolves a ChainDefinitionLoader from the factory and
// reads chain YAML from dir. Defaults to the built-in capability registry so
// callers don't have to thread it through every time.
func LoadChainDefinitions(ctx context.Context, newLoader ChainLoaderFactory, dir string) ([]policy.ChainDefinition, error) {
	loader, err := newLoader()
	if err != nil {
		return nil, fmt.Errorf("create chain loader: %w", err)
	}
	return loader.LoadChains(ctx, dir, capabilities.Builtin())
}

// LoadChainDefinitionsWith is the form for callers that want a custom registry
// (test fakes, alternative capability sets).
func LoadChainDefinitionsWith(ctx context.Context, newLoader ChainLoaderFactory, dir string, registry policy.CapabilityRegistry) ([]policy.ChainDefinition, error) {
	loader, err := newLoader()
	if err != nil {
		return nil, fmt.Errorf("create chain loader: %w", err)
	}
	return loader.LoadChains(ctx, dir, registry)
}

// Compile-time check: the ChainLoaderFactory must produce a value satisfying
// the ChainDefinitionLoader port. This catches regressions where the factory
// signature drifts from the port without a build break at the use site.
var _ func() (appcontracts.ChainDefinitionLoader, error) = ChainLoaderFactory(nil)
