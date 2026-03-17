package compose

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/domain/asset"
)

// LoadSnapshots is a convenience wrapper that loads snapshots via the given provider.
func LoadSnapshots(ctx context.Context, p *Provider, dir string) ([]asset.Snapshot, error) {
	return p.LoadSnapshots(ctx, dir)
}

// LoadSnapshots loads observations from the specified directory using
// the provider's configured repository.
func (p *Provider) LoadSnapshots(ctx context.Context, dir string) ([]asset.Snapshot, error) {
	if p.ObsRepoFunc == nil {
		return nil, fmt.Errorf("observation repository function not configured")
	}

	repo, err := p.ObsRepoFunc()
	if err != nil {
		return nil, fmt.Errorf("initializing observation repository: %w", err)
	}

	result, err := repo.LoadSnapshots(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading observations from %q: %w", dir, err)
	}

	return result.Snapshots, nil
}
