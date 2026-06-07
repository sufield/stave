package validate

import (
	"fmt"
	"io"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/internal/cli/ui"
)

// renderPayload carries everything the validation renderers need. The JSON
// and template renderers consume the externalized Report DTO; the text
// renderer additionally needs the original service result to derive
// diagnostics and summary counts.
type renderPayload struct {
	result *appvalidation.Report
	report Report
}

// Renderer is the polymorphic format-dispatch interface for the
// `apply validate` output. Concrete implementations delegate to the
// existing helpers (outjson.WriteValidation / ui.ExecuteTemplate /
// Reporter.writeText) so the rendered bytes are byte-identical to the
// pre-Renderer-pattern output.
//
// New formats add an implementation here and a factory case in NewRenderer.
type Renderer interface {
	Render(w io.Writer, payload renderPayload) error
}

// JSONRenderer writes the complete JSON validation output.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, payload renderPayload) error {
	if err := outjson.WriteValidation(w, payload.report); err != nil {
		return fmt.Errorf("write JSON validation output: %w", err)
	}
	return nil
}

// TemplateRenderer renders the report through a user-supplied template file.
// The format string carries the template path.
type TemplateRenderer struct {
	template string
}

// Render implements Renderer.
func (t TemplateRenderer) Render(w io.Writer, payload renderPayload) error {
	if err := ui.ExecuteTemplate(w, t.template, payload.report); err != nil {
		return fmt.Errorf("execute output template: %w", err)
	}
	return nil
}

// TextRenderer writes the default human-readable text output.
type TextRenderer struct {
	reporter *Reporter
}

// Render implements Renderer.
func (t TextRenderer) Render(w io.Writer, payload renderPayload) error {
	return t.reporter.writeText(payload.result, payload.report)
}

// NewRenderer maps a format string to its concrete Renderer, preserving the
// exact branching semantics of the previous switch:
//   - "json" -> JSONRenderer
//   - "" or "text" -> TextRenderer (the default)
//   - any other non-empty value -> TemplateRenderer (the format is a
//     template path)
//
// The text renderer delegates back to the Reporter for its presentation
// helpers, so the factory takes the Reporter that owns this output.
func NewRenderer(format string, reporter *Reporter) (Renderer, error) {
	switch {
	case format == string(appcontracts.FormatJSON):
		return JSONRenderer{}, nil
	case format != "" && format != string(appcontracts.FormatText):
		return TemplateRenderer{template: format}, nil
	default:
		return TextRenderer{reporter: reporter}, nil
	}
}
