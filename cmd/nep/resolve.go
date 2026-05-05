package nep

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// loadSnapshots loads snapshots from a file, supporting both bundle format
// ({"snapshots": [...]}) and single snapshot format ({"schema_version": "obs.v0.1", ...}).
func loadSnapshots(path string) ([]asset.Snapshot, error) {
	snaps, err := observations.LoadBundle(path)
	if err == nil && len(snaps) > 0 {
		return snaps, nil
	}
	// Fall back: try parsing as a single snapshot.
	data, readErr := fsutil.ReadFileLimited(path)
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", path, readErr)
	}
	var single asset.Snapshot
	if jsonErr := json.Unmarshal(data, &single); jsonErr != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, jsonErr)
	}
	if len(single.Assets) > 0 || len(single.Identities) > 0 {
		return []asset.Snapshot{single}, nil
	}
	return nil, fmt.Errorf("no snapshot data in %s", path)
}
