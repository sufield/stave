package report

import (
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	reportrender "github.com/sufield/stave/internal/adapters/output/report"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	corereport "github.com/sufield/stave/internal/core/report"
)

// reportPayload carries everything the renderers need to emit a report.
// It bundles the loaded evaluation with the rendering knobs so the
// Renderer interface can stay format-agnostic.
type reportPayload struct {
	Eval            corereport.Assessment
	StaveVersion    string
	DefaultTemplate string
	TemplatePath    string
	Quiet           bool
}

// Renderer is the polymorphic format-dispatch interface for
// `stave report`. Concrete implementations delegate to
// reportrender.RenderJSON / reportrender.RenderText.
//
// Two formats: text (default), json.
type Renderer interface {
	Render(w io.Writer, p reportPayload) error
}

// JSONRenderer emits the evaluation as the report JSON view model.
type JSONRenderer struct{}

// Render implements Renderer. It wraps the writer through
// compose.ResolveStdout so quiet mode discards machine output the
// same way the previous inline dispatch did.
func (JSONRenderer) Render(w io.Writer, p reportPayload) error {
	out := compose.ResolveStdout(w, p.Quiet, appcontracts.FormatJSON)
	if err := reportrender.RenderJSON(p.Eval, p.StaveVersion, out); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// TextRenderer emits the evaluation through the text/table template.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, p reportPayload) error {
	if err := reportrender.RenderText(p.Eval, reportrender.RenderTextOptions{
		StaveVersion:    p.StaveVersion,
		DefaultTemplate: p.DefaultTemplate,
		TemplatePath:    p.TemplatePath,
		Writer:          w,
		Quiet:           p.Quiet,
	}); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// NewRenderer maps a typed output format to its concrete Renderer.
// The format enum is validated upstream at the flag boundary, so an
// unknown format here is defensive: it surfaces an explicit error
// rather than silently falling back to a default.
func NewRenderer(format appcontracts.OutputFormat) (Renderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return JSONRenderer{}, nil
	case appcontracts.FormatText:
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
