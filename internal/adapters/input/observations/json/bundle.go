package json

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ObservationBundle represents a bundled observations file containing multiple snapshots.
type ObservationBundle struct {
	SchemaVersion kernel.Schema    `json:"schema_version"`
	Snapshots     []asset.Snapshot `json:"snapshots"`
}

// LoadBundle reads and unmarshals an observation bundle from the given path.
func LoadBundle(path string) ([]asset.Snapshot, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read observations file: %w", err)
	}
	var bundle ObservationBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse observations JSON: %w", err)
	}
	return bundle.Snapshots, nil
}
