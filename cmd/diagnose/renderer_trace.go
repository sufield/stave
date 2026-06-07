package diagnose

import (
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

// TraceRenderer is the polymorphic format-dispatch interface for
// `stave trace`. Concrete implementations delegate to the trace
// result's own RenderJSON / RenderText methods.
//
// Two formats: json and text (default).
type TraceRenderer interface {
	Render(w io.Writer, result evaluation.TraceRenderer) error
}

// TraceJSONRenderer emits the trace result as JSON.
type TraceJSONRenderer struct{}

// Render implements TraceRenderer.
func (TraceJSONRenderer) Render(w io.Writer, result evaluation.TraceRenderer) error {
	if err := result.RenderJSON(w); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// TraceTextRenderer emits the trace result as human-readable text.
type TraceTextRenderer struct{}

// Render implements TraceRenderer.
func (TraceTextRenderer) Render(w io.Writer, result evaluation.TraceRenderer) error {
	if err := result.RenderText(w); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// NewTraceRenderer maps a typed OutputFormat to its concrete renderer.
// The enum is validated upstream at flag-parse time, so an unknown
// format here is defensive: it surfaces an explicit error rather than
// silently falling through to a default.
func NewTraceRenderer(format appcontracts.OutputFormat) (TraceRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return TraceJSONRenderer{}, nil
	case appcontracts.FormatText:
		return TraceTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
