package snapshot

import (
	"context"
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile

// Compatibility aliases used across tests and builders in this package.
type RetentionTiersMap = map[string]projconfig.RetentionTierConfig
type TierMappingRule = projconfig.TierMappingRule

func listObservationSnapshotFilesRecursive(ctx context.Context, observationsDir string, excludeDirs []string) ([]snapshotFile, error) {
	loader, err := compose.ActiveProvider().NewSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	return pruner.ListSnapshotFilesRecursiveWithLoader(ctx, observationsDir, excludeDirs, loader)
}
