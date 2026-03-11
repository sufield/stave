// Package observations provides JSON output for normalized observation snapshots.
package observations

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
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

// WriteObservations marshals snapshots as obs.v0.1 JSON and writes the file safely.
func (JSONWriter) WriteObservations(path string, snapshots []asset.Snapshot, overwrite, allowSymlink bool) error {
	return WriteJSON(WriteRequest{
		Path:          path,
		SchemaVersion: kernel.SchemaObservation,
		Snapshots:     snapshots,
		Overwrite:     overwrite,
		AllowSymlink:  allowSymlink,
	})
}

// WriteJSON marshals observations to indented JSON and writes the file safely.
func WriteJSON(req WriteRequest) error {
	output := struct {
		SchemaVersion kernel.Schema    `json:"schema_version"`
		Snapshots     []asset.Snapshot `json:"snapshots"`
	}{
		SchemaVersion: req.SchemaVersion,
		Snapshots:     req.Snapshots,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal observations: %w", err)
	}

	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = req.Overwrite
	opts.AllowSymlink = req.AllowSymlink
	if err := fsutil.SafeWriteFile(req.Path, data, opts); err != nil {
		return fmt.Errorf("write observations file: %w", err)
	}
	return nil
}
