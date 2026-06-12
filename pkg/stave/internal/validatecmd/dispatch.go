package validatecmd

import (
	"fmt"
	"io"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appvalidation "github.com/sufield/stave/internal/app/validation"
)

// renderPayload carries everything the validation renderers need. The JSON
// and template renderers consume the externalized Report DTO; the text
// renderer additionally needs the original service result to derive
// diagnostics and summary counts.
type renderPayload struct {
	result *appvalidation.Report
	report Report
}

// Renderer is the polymorphic format-dispatch interface for the validate
// output. Concrete implementations delegate to outjson.WriteValidation, the
// Template callback, or Reporter.writeText so the rendered bytes are
// byte-identical to the command's pre-facade output.
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
// The format string carries the template path; execution is delegated to the
// command-provided TemplateFunc (backed by ui.ExecuteTemplate).
type TemplateRenderer struct {
	template string
	exec     TemplateFunc
}

// Render implements Renderer.
func (t TemplateRenderer) Render(w io.Writer, payload renderPayload) error {
	if err := t.exec(w, t.template, payload.report); err != nil {
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
// exact branching semantics of the command's pre-facade switch:
//   - "json" -> JSONRenderer
//   - "" or "text" -> TextRenderer (the default)
//   - any other non-empty value -> TemplateRenderer (the format is a
//     template path)
func NewRenderer(format string, reporter *Reporter) (Renderer, error) {
	switch {
	case format == string(appcontracts.FormatJSON):
		return JSONRenderer{}, nil
	case format != "" && format != string(appcontracts.FormatText):
		return TemplateRenderer{template: format, exec: reporter.Template}, nil
	default:
		return TextRenderer{reporter: reporter}, nil
	}
}
