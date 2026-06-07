package diagnose

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// ExplainResultRenderer is the polymorphic format-dispatch interface
// for `stave explain`. Concrete implementations delegate to
// jsonutil.WriteIndented (JSON) or text.WriteExplainText (text).
//
// Two formats: json and text (default).
type ExplainResultRenderer interface {
	Render(w io.Writer, result appcontracts.ExplainResult) error
}

// ExplainResultJSONRenderer emits the explain result as indented JSON.
type ExplainResultJSONRenderer struct{}

// Render implements ExplainResultRenderer.
func (ExplainResultJSONRenderer) Render(w io.Writer, result appcontracts.ExplainResult) error {
	if err := jsonutil.WriteIndented(w, result); err != nil {
		return fmt.Errorf("write explain JSON: %w", err)
	}
	return nil
}

// ExplainResultTextRenderer emits the explain result as human-readable
// text.
type ExplainResultTextRenderer struct{}

// Render implements ExplainResultRenderer.
func (ExplainResultTextRenderer) Render(w io.Writer, result appcontracts.ExplainResult) error {
	if err := text.WriteExplainText(w, result); err != nil {
		return fmt.Errorf("write explain text: %w", err)
	}
	return nil
}

// NewExplainResultRenderer maps a typed OutputFormat to its concrete
// renderer. The enum is validated upstream at flag-parse time, so an
// unknown format here is defensive: it surfaces an explicit error
// rather than silently falling through to a default.
func NewExplainResultRenderer(format appcontracts.OutputFormat) (ExplainResultRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return ExplainResultJSONRenderer{}, nil
	case appcontracts.FormatText:
		return ExplainResultTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
