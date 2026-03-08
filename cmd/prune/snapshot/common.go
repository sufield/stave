package snapshot

import (
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile

// Compatibility aliases used across tests and builders in this package.
type RetentionTiersMap = cmdutil.RetentionTiersMap
type TierMappingRule = cmdutil.TierMappingRule

func writeJSON(w io.Writer, v any) error {
	return jsonutil.WriteIndented(w, v)
}

func listObservationSnapshotFilesRecursive(observationsDir string, excludeDirs []string) ([]snapshotFile, error) {
	loader, err := cmdutil.NewSnapshotObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	return pruner.ListSnapshotFilesRecursiveWithLoader(observationsDir, excludeDirs, loader)
}
