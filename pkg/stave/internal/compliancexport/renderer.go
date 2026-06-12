package compliancexport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Renderer is the polymorphic format-dispatch interface the
// compliance export uses to choose between table / markdown / JSON
// output. Concrete implementations live alongside their format-
// specific helpers (renderJSON / renderTable / renderMarkdown);
// new formats add an implementation here and a factory case in
// NewRenderer rather than another `switch opts.Format` block.
//
// Render accepts `any` so the renderer set covers both the single-
// framework EvidenceExport and the multi-framework
// CompositeEvidenceExport. The concrete renderer type-asserts on
// the value it receives.
type Renderer interface {
	Render(w io.Writer, export any) error
}

// JSONRenderer encodes the export as indented JSON. Valid for both
// single and composite exports because both types have JSON tags.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, export any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(export)
}

// TableRenderer dispatches to the format-specific table renderer
// based on the export type.
type TableRenderer struct {
	Verbose bool
}

// Render implements Renderer.
func (r TableRenderer) Render(w io.Writer, export any) error {
	switch e := export.(type) {
	case *EvidenceExport:
		return renderTable(w, e, r.Verbose)
	case CompositeEvidenceExport:
		renderCompositeTable(w, e)
		return nil
	}
	return fmt.Errorf("table renderer: unsupported export type %T", export)
}

// MarkdownRenderer dispatches to the format-specific markdown
// renderer based on the export type. Composite markdown reuses
// the table form because the composite renderer already produces
// a markdown-friendly layout.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, export any) error {
	switch e := export.(type) {
	case *EvidenceExport:
		return renderMarkdown(w, e)
	case CompositeEvidenceExport:
		renderCompositeTable(w, e)
		return nil
	}
	return fmt.Errorf("markdown renderer: unsupported export type %T", export)
}

// errOSCALRendererPlaceholder marks the OSCALRenderer as not
// reachable through the generic interface — OSCAL export needs
// inputs the EvidenceExport projection drops (multi-framework
// profiles, raw assessments, snapshot time). The factory still
// returns it so callers can detect the format choice; run.go
// branches into renderOSCAL directly when this renderer is
// returned.
var errOSCALRendererPlaceholder = errors.New("oscal renderer: dispatch via renderOSCAL, not Render(any)")

// OSCALRenderer is a marker type returned by NewRenderer when
// opts.Format == "oscal". The OSCAL pipeline needs richer inputs
// than Render(any) carries, so callers detect this renderer with
// a type-assertion and call renderOSCAL with the full inputs.
type OSCALRenderer struct{}

// Render implements Renderer for interface compliance; always
// returns the placeholder error so a caller that forgets to
// dispatch via renderOSCAL fails loud.
func (OSCALRenderer) Render(_ io.Writer, _ any) error {
	return errOSCALRendererPlaceholder
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats so the caller can surface
// a UserError consistently — both the single-framework and
// composite paths previously diverged here, with one returning
// an error and the other defaulting to JSON. The factory unifies
// behaviour: unknown formats are an explicit input error.
func NewRenderer(format string, verbose bool) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "table":
		return TableRenderer{Verbose: verbose}, nil
	case "markdown":
		return MarkdownRenderer{}, nil
	case "oscal":
		return OSCALRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format: %q", format)
}
