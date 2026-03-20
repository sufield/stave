package snapshot

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/adapters/pruner"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// listSnapshotFilesRecursive identifies snapshot files by traversing the directory tree.
// It requires an explicit SnapshotReader to avoid reliance on global providers.
func listSnapshotFilesRecursive(ctx context.Context, loader appcontracts.SnapshotReader, dir string, excludeDirs []string) ([]pruner.SnapshotFile, error) {
	files, err := pruner.ListSnapshotFilesRecursiveWithLoader(ctx, dir, excludeDirs, loader)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots in %q: %w", dir, err)
	}
	return files, nil
}
