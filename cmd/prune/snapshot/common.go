package snapshot

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile

// Compatibility aliases used across tests and builders in this package.
type RetentionTiersMap = cmdutil.RetentionTiersMap
type TierMappingRule = cmdutil.TierMappingRule

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func listObservationSnapshotFilesRecursive(observationsDir string, excludeDirs []string) ([]snapshotFile, error) {
	loader, err := cmdutil.NewSnapshotObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	return pruner.ListSnapshotFilesRecursiveWithLoader(observationsDir, excludeDirs, loader)
}
