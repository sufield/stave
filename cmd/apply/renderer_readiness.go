package apply

import (
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	validation "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// ReadinessRenderer is the polymorphic format-dispatch interface for
// the `stave apply --dry-run` readiness report. Distinct from the
// package's NewOnlyRenderer because the cmd/apply package owns
// multiple output surfaces (main apply, new-only filter, readiness);
// each surface gets its own narrow interface rather than one
// over-general one.
//
// The text renderer writes its summary to stdout and progress/hint
// messages to stderr, so Render takes both writers; the JSON renderer
// ignores stderr.
//
// Two formats: json + the default human-readable text.
type ReadinessRenderer interface {
	Render(stdout, stderr io.Writer, report validation.ReadinessAssessment) error
}

// ReadinessJSONRenderer encodes the readiness report as indented JSON,
// enriched with the CLI-specific next_command field.
type ReadinessJSONRenderer struct{}

// Render implements ReadinessRenderer.
func (ReadinessJSONRenderer) Render(stdout, _ io.Writer, report validation.ReadinessAssessment) error {
	if err := jsonutil.WriteIndented(stdout, readinessJSONReport{
		ReadinessAssessment: report,
		NextCommand:         report.NextCommand(),
	}); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// ReadinessTextRenderer writes the default human-readable plan summary.
type ReadinessTextRenderer struct{}

// Render implements ReadinessRenderer.
func (ReadinessTextRenderer) Render(stdout, stderr io.Writer, report validation.ReadinessAssessment) error {
	rep := &Reporter{Stdout: stdout, Stderr: stderr}
	return rep.ReportPlan(report)
}

// NewReadinessRenderer maps a typed OutputFormat to its concrete
// renderer. The format enum is validated upstream at flag-parse time,
// so the unknown-format branch is defensive: it returns an explicit
// error rather than silently falling through to text rendering.
func NewReadinessRenderer(format appcontracts.OutputFormat) (ReadinessRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return ReadinessJSONRenderer{}, nil
	case appcontracts.FormatText:
		return ReadinessTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
