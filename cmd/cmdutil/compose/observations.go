package compose

import (
	"context"
	"fmt"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/asset"
)

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

// LatestSnapshot returns the most recent snapshot by CapturedAt from a slice.
func LatestSnapshot(snapshots []asset.Snapshot) (asset.Snapshot, error) {
	if len(snapshots) == 0 {
		return asset.Snapshot{}, appeval.ErrNoSnapshots
	}
	latest := snapshots[0]
	for _, s := range snapshots[1:] {
		if s.CapturedAt.After(latest.CapturedAt) {
			latest = s
		}
	}
	return latest, nil
}
