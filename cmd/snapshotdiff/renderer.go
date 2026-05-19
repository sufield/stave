package snapshotdiff

import (
	"encoding/json"
	"fmt"
	"io"

	appdiff "github.com/sufield/stave/internal/app/catalogdiff"
	"github.com/sufield/stave/internal/app/snapshotdiff"
)

// `stave snapshotdiff` has two output surfaces — a catalog diff
// (Delta) and an observation snapshot diff (DiffResult). Each
// renders a different payload type so each gets its own Renderer
// interface, following the multi-payload recipe established by
// cmd/consolidate and cmd/nep.

// --- CatalogRenderer ---

// CatalogRenderer renders a catalog-diff Delta — the result of
// comparing two control catalogs.
type CatalogRenderer interface {
	Render(w io.Writer, d *appdiff.Delta) error
}

// CatalogJSONRenderer encodes the Delta as indented JSON.
type CatalogJSONRenderer struct{}

// Render implements CatalogRenderer.
func (CatalogJSONRenderer) Render(w io.Writer, d *appdiff.Delta) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

// CatalogTableRenderer writes the default human-readable diff table.
type CatalogTableRenderer struct{}

// Render implements CatalogRenderer.
func (CatalogTableRenderer) Render(w io.Writer, d *appdiff.Delta) error {
	_, err := fmt.Fprint(w, appdiff.FormatTable(d))
	return err
}

// NewCatalogRenderer maps a format string to a CatalogRenderer.
func NewCatalogRenderer(format string) (CatalogRenderer, error) {
	switch format {
	case "json":
		return CatalogJSONRenderer{}, nil
	case "table", "":
		return CatalogTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// --- SnapshotRenderer ---

// SnapshotRenderer renders an observation-snapshot diff result —
// the structural differences between two snapshots of the same
// asset graph captured at different points in time.
type SnapshotRenderer interface {
	Render(w io.Writer, r *snapshotdiff.DiffResult) error
}

// SnapshotJSONRenderer encodes the DiffResult as indented JSON.
type SnapshotJSONRenderer struct{}

// Render implements SnapshotRenderer.
func (SnapshotJSONRenderer) Render(w io.Writer, r *snapshotdiff.DiffResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// SnapshotTextRenderer writes the default human-readable summary.
type SnapshotTextRenderer struct{}

// Render implements SnapshotRenderer.
func (SnapshotTextRenderer) Render(w io.Writer, r *snapshotdiff.DiffResult) error {
	return writeText(w, r)
}

// NewSnapshotRenderer maps a format string to a SnapshotRenderer.
func NewSnapshotRenderer(format string) (SnapshotRenderer, error) {
	switch format {
	case "json":
		return SnapshotJSONRenderer{}, nil
	case "table", "":
		return SnapshotTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}
