package coverage

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/fieldcov"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave coverage`. Concrete implementations delegate to
// fieldcov.WriteTable / encoding/json so the rendered bytes are
// byte-identical to the pre-Renderer-pattern output.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, report *fieldcov.Report) error
}

// JSONRenderer encodes the report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, report *fieldcov.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, report *fieldcov.Report) error {
	fieldcov.WriteTable(w, report)
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous switch already
// rejected unknown values explicitly, so this is the same behaviour
// surfaced through the factory.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: table, json)", format)
}
