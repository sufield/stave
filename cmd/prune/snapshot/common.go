package snapshot

import (
	"context"
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile

// Compatibility aliases used across tests and builders in this package.
type RetentionTiersMap = map[string]projconfig.RetentionTierConfig
type TierMappingRule = projconfig.TierMappingRule

// listSnapshotFilesRecursive identifies snapshot files by traversing the directory tree.
// It requires an explicit SnapshotReader to avoid reliance on global providers.
func listSnapshotFilesRecursive(ctx context.Context, loader appcontracts.SnapshotReader, dir string, excludeDirs []string) ([]snapshotFile, error) {
	files, err := pruner.ListSnapshotFilesRecursiveWithLoader(ctx, dir, excludeDirs, loader)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots in %q: %w", dir, err)
	}
	return files, nil
}
