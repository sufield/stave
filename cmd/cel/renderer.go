package cel

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/celeval"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave cel eval`. Concrete implementations delegate to
// jsonutil.WriteIndented / renderCELText so the rendered bytes are
// byte-identical to the pre-Renderer-pattern output.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, result *celeval.EvalResult) error
}

// JSONRenderer encodes the evaluation result as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, result *celeval.EvalResult) error {
	if err := jsonutil.WriteIndented(w, result); err != nil {
		return fmt.Errorf("write JSON output: %w", err)
	}
	return nil
}

// TextRenderer writes the default human-readable summary.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, result *celeval.EvalResult) error {
	return renderCELText(w, result)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the empty string maps to
// the default text format.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json)", format)
}
