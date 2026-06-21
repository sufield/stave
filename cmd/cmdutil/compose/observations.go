package compose

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

// LoadSnapshotsFrom loads observations from the specified directory using
// the provided factory function.
func LoadSnapshotsFrom(ctx context.Context, newObs ObsRepoFactory, dir string) ([]asset.Snapshot, error) {
	repo, err := newObs()
	if err != nil {
		return nil, fmt.Errorf("initializing observation repository: %w", err)
	}

	result, err := repo.LoadSnapshots(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading observations from %q: %w", dir, err)
	}

	return result.Snapshots, nil
}
