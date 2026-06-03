package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/contracts"
	er "github.com/sufield/stave/internal/app/execreport"
)

// Renderer is the polymorphic format-dispatch interface for the
// executive `stave report` command. Two formats: json (default) and
// markdown. Factory takes contracts.OutputFormat directly because
// the report command uses the typed enum for --format (unlike the
// string-based factories elsewhere in this codebase).
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r *er.Report) error
}

// JSONRenderer encodes the report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *er.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// MarkdownRenderer writes the markdown form of the executive report.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, r *er.Report) error {
	if err := er.WriteMarkdown(w, r); err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}

// NewRenderer maps a contracts.OutputFormat to its concrete Renderer.
// Returns an error for formats this command does not support; the
// previous default branch silently rendered as JSON for any non-
// markdown value, which masked typos like `--format yaml`. The
// explicit error is the documented unification from
// renderer-pattern-debt.md.
func NewRenderer(format contracts.OutputFormat) (Renderer, error) {
	switch format {
	case contracts.FormatJSON, "":
		return JSONRenderer{}, nil
	case contracts.FormatMarkdown:
		return MarkdownRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: json | markdown)", format)
}
