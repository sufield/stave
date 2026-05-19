package gaps

import (
	"encoding/json"
	"fmt"
	"io"

	appgaps "github.com/sufield/stave/internal/app/gaps"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave gaps`. Concrete implementations delegate to writeText
// (cmd/gaps/output.go) and encoding/json. The validation-switch +
// dispatch-switch pair that previously bracketed the run() body
// collapses to a single NewRenderer call at the top.
//
// TextRenderer carries TopN because writeText takes the top-N action
// count as a parameter; the report itself doesn't carry it.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r appgaps.Report) error
}

// JSONRenderer encodes the report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r appgaps.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

// TextRenderer writes the human-readable gap report. Carries the
// action-plan TopN limit because writeText takes it as a parameter
// and the Report struct does not.
type TextRenderer struct {
	TopN int
}

// Render implements Renderer.
func (t TextRenderer) Render(w io.Writer, r appgaps.Report) error {
	if err := writeText(w, r, t.TopN); err != nil {
		return fmt.Errorf("render text: %w", err)
	}
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous run() body had
// a validation switch at the top with this exact message.
func NewRenderer(format string, topN int) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{TopN: topN}, nil
	}
	return nil, fmt.Errorf("--format must be text | json (got %q)", format)
}
