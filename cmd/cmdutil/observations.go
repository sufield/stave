package cmdutil

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/domain/asset"
)

// LoadSnapshots creates an observation repository and loads snapshots from dir.
func LoadSnapshots(ctx context.Context, dir string) ([]asset.Snapshot, error) {
	repo, err := NewObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	result, err := repo.LoadSnapshots(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("load observations: %w", err)
	}
	return result.Snapshots, nil
}
