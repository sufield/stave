package mapcmd

import (
	"encoding/json"
	"fmt"
	"io"

	appcoverage "github.com/sufield/stave/internal/app/coverage"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave map`. Four formats: json, navigator (also JSON but a
// different projection — the ATT&CK Navigator layer schema),
// markdown, and the default human-readable table.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r *appcoverage.CoverageReport) error
}

// JSONRenderer encodes the raw coverage report.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *appcoverage.CoverageReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// NavigatorRenderer encodes the report as an ATT&CK Navigator layer
// (a different JSON projection of the same data).
type NavigatorRenderer struct{}

// Render implements Renderer.
func (NavigatorRenderer) Render(w io.Writer, r *appcoverage.CoverageReport) error {
	layer := appcoverage.NavigatorLayer(r)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(layer)
}

// MarkdownRenderer writes the markdown coverage report.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, r *appcoverage.CoverageReport) error {
	writeMarkdown(w, r)
	return nil
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, r *appcoverage.CoverageReport) error {
	writeTable(w, r)
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as a table.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "navigator":
		return NavigatorRenderer{}, nil
	case "markdown":
		return MarkdownRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | navigator | markdown)", format)
}
