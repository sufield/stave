package observations

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ObservationBundle represents a bundled observations file containing multiple snapshots.
type ObservationBundle struct {
	SchemaVersion kernel.Schema    `json:"schema_version"`
	Snapshots     []asset.Snapshot `json:"snapshots"`
}

// ParseBundle unmarshals observation bundle JSON from raw bytes
// and applies minimum-shape validation: the top-level
// `snapshots` array must be present and non-empty, and every
// contained snapshot must carry a non-zero `captured_at`
// timestamp. Without these checks, a single-snapshot file
// shaped like a flat snapshot (no `snapshots` key) would
// unmarshal into an empty bundle and look like
// success-with-no-data; missing timestamps would propagate
// into duration arithmetic and produce silent inconclusives.
// Standard directory loading runs equivalent checks via
// ObservationLoader.process; bundle loading must match.
func ParseBundle(data []byte) ([]asset.Snapshot, error) {
	var bundle ObservationBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse observations JSON: %w", err)
	}
	if len(bundle.Snapshots) == 0 {
		return nil, fmt.Errorf("observation bundle contains no snapshots (expected a top-level `snapshots` array)")
	}
	for i := range bundle.Snapshots {
		if bundle.Snapshots[i].CapturedAt.IsZero() {
			return nil, fmt.Errorf("observation bundle snapshot %d is missing required `captured_at` timestamp", i)
		}
	}
	return bundle.Snapshots, nil
}

// LoadBundle reads and unmarshals an observation bundle from the given path.
func LoadBundle(path string) ([]asset.Snapshot, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read observations file: %w", err)
	}
	return ParseBundle(data)
}
