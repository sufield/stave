package doctor

import (
	"encoding/json"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/setup"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave doctor`. Concrete implementations delegate to the package's
// existing report writers, preserving byte-for-byte output.
//
// Two formats: text (default) and json.
type Renderer interface {
	Render(w io.Writer, resp setup.DoctorResponse) error
}

// JSONRenderer emits the doctor report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, resp setup.DoctorResponse) error {
	payload := struct {
		Ready  bool                `json:"ready"`
		Checks []setup.DoctorCheck `json:"checks"`
	}{
		Ready:  resp.AllPassed,
		Checks: resp.Checks,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode doctor report JSON: %w", err)
	}
	return nil
}

// TextRenderer emits the doctor report as human-readable text.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, resp setup.DoctorResponse) error {
	for _, c := range resp.Checks {
		if _, err := fmt.Fprintf(w, "[%s] %s: %s\n", c.Status, c.Name, c.Message); err != nil {
			return fmt.Errorf("write doctor check status: %w", err)
		}
		if c.Fix != "" {
			if _, err := fmt.Fprintf(w, "      Fix: %s\n", c.Fix); err != nil {
				return fmt.Errorf("write doctor check fix: %w", err)
			}
		}
	}
	return nil
}

// NewRenderer maps a typed OutputFormat to its concrete Renderer.
// Doctor supports text (default) and json. An unknown format yields
// an explicit error; this is defensive — the format enum is validated
// upstream at flag-parse time.
func NewRenderer(format appcontracts.OutputFormat) (Renderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return JSONRenderer{}, nil
	case appcontracts.FormatText:
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
