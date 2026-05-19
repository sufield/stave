package inventory

import (
	"fmt"
	"io"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave snapshot inventory`. Concrete implementations delegate to
// the existing renderInventoryJSON / renderInventoryOpenMetrics /
// renderInventoryTable helpers.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r *inventoryReport) error
}

// JSONRenderer encodes the inventory report as JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *inventoryReport) error {
	return renderInventoryJSON(w, r)
}

// OpenMetricsRenderer emits the inventory report in OpenMetrics
// text-exposition form.
type OpenMetricsRenderer struct{}

// Render implements Renderer.
func (OpenMetricsRenderer) Render(w io.Writer, r *inventoryReport) error {
	return renderInventoryOpenMetrics(w, r)
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, r *inventoryReport) error {
	return renderInventoryTable(w, r)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as table.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "openmetrics":
		return OpenMetricsRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | openmetrics)", format)
}
