package compose

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/domain/asset"
)

// LoadSnapshots is a convenience wrapper that uses the default provider
// to load snapshots from a directory.
func LoadSnapshots(ctx context.Context, dir string) ([]asset.Snapshot, error) {
	return defaultProvider.LoadSnapshots(ctx, dir)
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
