package score

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/pkg/stave"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave score`. Concrete implementations delegate to writeTable /
// writeOpenMetrics / encoding/json so the rendered bytes are
// byte-identical to the pre-Renderer-pattern output.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r stave.ScoreResult) error
}

// JSONRenderer encodes the score result as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r stave.ScoreResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// OpenMetricsRenderer writes the OpenMetrics gauge exposition.
type OpenMetricsRenderer struct{}

// Render implements Renderer.
func (OpenMetricsRenderer) Render(w io.Writer, r stave.ScoreResult) error {
	writeOpenMetrics(w, r)
	return nil
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, r stave.ScoreResult) error {
	writeTable(w, r)
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the empty string maps to the
// package default (table) to preserve the prior switch behaviour.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "openmetrics":
		return OpenMetricsRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: table, json, openmetrics)", format)
}
