package budget

import (
	"encoding/json"
	"fmt"
	"io"

	appbudget "github.com/sufield/stave/internal/app/budget"
)

// Renderer is the polymorphic format-dispatch interface for the
// budget command's output. Concrete implementations delegate to the
// existing writeTable / writeMarkdown / writeOpenMetrics helpers so
// the rendered bytes are byte-identical to the pre-Renderer-pattern
// output. The only behavioural change is that unknown formats become
// an explicit factory error instead of silently rendering as a table.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r appbudget.Report) error
}

// JSONRenderer encodes the report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r appbudget.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// OpenMetricsRenderer writes the OpenMetrics text-exposition shape.
type OpenMetricsRenderer struct{}

// Render implements Renderer.
func (OpenMetricsRenderer) Render(w io.Writer, r appbudget.Report) error {
	writeOpenMetrics(w, r)
	return nil
}

// MarkdownRenderer writes the markdown report shape.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, r appbudget.Report) error {
	writeMarkdown(w, r)
	return nil
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, r appbudget.Report) error {
	writeTable(w, r)
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as a table, which masked typos. The explicit
// error is the documented unification behaviour from
// renderer-pattern-debt.md.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "openmetrics":
		return OpenMetricsRenderer{}, nil
	case "markdown":
		return MarkdownRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | openmetrics | markdown)", format)
}
