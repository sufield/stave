package readiness

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/readiness"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave readiness`. Concrete implementations delegate to
// writeText (cmd/readiness/output.go) and encoding/json so the
// rendered bytes are byte-identical to the pre-Renderer-pattern
// output. The validation-switch + dispatch-switch pair that
// previously bracketed the run() body collapses to a single
// NewRenderer call at the top.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r readiness.Report) error
}

// JSONRenderer encodes the report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r readiness.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

// TextRenderer writes the human-readable readiness assessment.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, r readiness.Report) error {
	if err := writeText(w, r); err != nil {
		return fmt.Errorf("render text: %w", err)
	}
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous run() body
// had a validation switch at the top with this exact message.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("--format must be text | json (got %q)", format)
}
