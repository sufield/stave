package env

import (
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave env list`. Concrete implementations delegate to
// jsonutil.WriteIndented (JSON) or renderEnvText (text).
//
// Two formats: json, text.
type Renderer interface {
	Render(w io.Writer, entries []Entry) error
}

// JSONRenderer emits the entries as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, entries []Entry) error {
	if err := jsonutil.WriteIndented(w, entries); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// TextRenderer emits the entries as the human-readable tabular text form.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, entries []Entry) error {
	return renderEnvText(w, entries)
}

// NewRenderer maps a typed OutputFormat to its concrete Renderer.
// Bad formats are rejected at flag-parse time, so the unknown-format
// branch is defensive.
func NewRenderer(format appcontracts.OutputFormat) (Renderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return JSONRenderer{}, nil
	case appcontracts.FormatText:
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
