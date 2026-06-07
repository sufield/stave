package scorecard

import (
	"encoding/json"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appsc "github.com/sufield/stave/internal/app/scorecard"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave scorecard`. Concrete implementations delegate to the
// package's existing encode/write helpers (encoding/json,
// writeMarkdown, writeTable).
//
// Three formats: json, markdown, table (default). FormatText routes
// to the table renderer, preserving the prior tagless switch where
// every non-json/non-markdown format fell through to writeTable.
type Renderer interface {
	Render(w io.Writer, r *appsc.Report) error
}

// JSONRenderer emits the report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *appsc.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// MarkdownRenderer emits the report as a Markdown table.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, r *appsc.Report) error {
	return writeMarkdown(w, r)
}

// TableRenderer emits the report as a column-aligned text table —
// the default format when no other is selected.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, r *appsc.Report) error {
	return writeTable(w, r)
}

// NewRenderer maps a typed OutputFormat to its concrete Renderer.
// Returns an error for unsupported formats; the bare format string is
// already validated upstream at the flag boundary, so this is a
// defensive guard rather than the primary validation point.
func NewRenderer(format appcontracts.OutputFormat) (Renderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return JSONRenderer{}, nil
	case appcontracts.FormatMarkdown:
		return MarkdownRenderer{}, nil
	case appcontracts.FormatTable, appcontracts.FormatText:
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: json | markdown | table)", format)
}
