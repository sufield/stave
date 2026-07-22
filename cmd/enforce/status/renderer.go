package status

import (
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/util/jsonutil"
	appstatus "github.com/sufield/stave/pkg/stave/status"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave status`. Concrete implementations delegate to
// jsonutil.WriteIndented (JSON) or appstatus.FormatText (text).
type Renderer interface {
	Render(w io.Writer, res appstatus.Result) error
}

// JSONRenderer emits the status result as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, res appstatus.Result) error {
	if err := jsonutil.WriteIndented(w, res); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// TextRenderer emits the status result as human-readable text.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, res appstatus.Result) error {
	if err := appstatus.FormatText(w, res); err != nil {
		return fmt.Errorf("render status text: %w", err)
	}
	return nil
}

// NewRenderer maps a typed OutputFormat to its concrete Renderer.
// The enum is validated upstream at flag-parse time, so an unknown
// format here is defensive: it surfaces an explicit error rather than
// silently falling through to a default.
func NewRenderer(format cmdutil.OutputFormat) (Renderer, error) {
	switch format {
	case cmdutil.FormatJSON:
		return JSONRenderer{}, nil
	case cmdutil.FormatText:
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
