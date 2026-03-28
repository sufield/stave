// Package observations provides JSON output for normalized observation snapshots.
package observations

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// WriteRequest controls how observations are serialized and persisted.
type WriteRequest struct {
	Path          string
	SchemaVersion kernel.Schema
	Snapshots     []asset.Snapshot
	Overwrite     bool
	AllowSymlink  bool
}

// JSONWriter implements the app-layer ObservationPersistence port.
type JSONWriter struct{}
