package cmdutil

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// LoadSnapshotFromPath reads a single observation snapshot file at path
// and unmarshals it into asset.Snapshot. The path is cleaned via
// fsutil.CleanUserPath because it comes from user-supplied flags.
//
// This is the single-file form. For directories of snapshots, use the
// ObservationRepository port. For multi-snapshot bundles, use the
// SnapshotBundleLoader port.
func LoadSnapshotFromPath(path string) (asset.Snapshot, error) {
	data, err := fsutil.ReadFileLimited(fsutil.CleanUserPath(path))
	if err != nil {
		return asset.Snapshot{}, fmt.Errorf("read snapshot %q: %w", path, err)
	}
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return asset.Snapshot{}, fmt.Errorf("parse snapshot %q: %w", path, err)
	}
	return snap, nil
}
