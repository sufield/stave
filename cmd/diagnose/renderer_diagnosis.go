package diagnose

import (
	"fmt"
	"io"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
)

// `stave diagnose` renders two distinct payloads through the Presenter:
// the standard diagnostic report and the single-finding deep-dive
// detail. Each payload gets its own Renderer interface keyed by the
// payload it renders; the factories share the typed-format contract but
// the concrete types and dispatch tables are per-payload. Same shape as
// cmd/nep's multi-payload convention.

// --- ReportRenderer ---

// ReportRenderer is the polymorphic format-dispatch interface for the
// standard diagnostic report. Concrete implementations delegate to
// outjson.WriteDiagnosis (JSON) or outtext.WriteDiagnosisReport (text).
//
// The text renderer carries the writer it will render to because the
// severity-label colorizer closure depends on the destination writer's
// TTY state.
type ReportRenderer interface {
	Render(w io.Writer, report *diagnosis.Report) error
}

// ReportJSONRenderer emits the diagnostic report as JSON.
type ReportJSONRenderer struct{}

// Render implements ReportRenderer.
func (ReportJSONRenderer) Render(w io.Writer, report *diagnosis.Report) error {
	if err := outjson.WriteDiagnosis(w, report); err != nil {
		return fmt.Errorf("write diagnosis JSON: %w", err)
	}
	return nil
}

// ReportTextRenderer emits the diagnostic report as human-readable text.
type ReportTextRenderer struct{}

// Render implements ReportRenderer.
func (ReportTextRenderer) Render(w io.Writer, report *diagnosis.Report) error {
	if err := outtext.WriteDiagnosisReport(w, report, func(level, msg string) string {
		return ui.SeverityLabel(level, msg, w)
	}); err != nil {
		return fmt.Errorf("write diagnosis text: %w", err)
	}
	return nil
}

// NewReportRenderer maps a typed OutputFormat to its concrete renderer.
// The enum is validated upstream at flag-parse time, so an unknown
// format here is defensive: it surfaces an explicit error rather than
// silently falling through to a default.
func NewReportRenderer(format appcontracts.OutputFormat) (ReportRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return ReportJSONRenderer{}, nil
	case appcontracts.FormatText:
		return ReportTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}

// --- DetailRenderer ---

// DetailRenderer is the polymorphic format-dispatch interface for the
// single-finding deep-dive result. Concrete implementations delegate to
// writeFindingDetailJSON (JSON) or outtext.WriteFindingDetail (text).
type DetailRenderer interface {
	Render(w io.Writer, detail *evaluation.FindingDetail) error
}

// DetailJSONRenderer emits the finding detail as JSON.
type DetailJSONRenderer struct{}

// Render implements DetailRenderer.
func (DetailJSONRenderer) Render(w io.Writer, detail *evaluation.FindingDetail) error {
	if err := writeFindingDetailJSON(w, detail); err != nil {
		return fmt.Errorf("write finding detail JSON: %w", err)
	}
	return nil
}

// DetailTextRenderer emits the finding detail as human-readable text.
type DetailTextRenderer struct{}

// Render implements DetailRenderer.
func (DetailTextRenderer) Render(w io.Writer, detail *evaluation.FindingDetail) error {
	if err := outtext.WriteFindingDetail(w, detail); err != nil {
		return fmt.Errorf("write finding detail text: %w", err)
	}
	return nil
}

// NewDetailRenderer maps a typed OutputFormat to its concrete renderer.
// The enum is validated upstream at flag-parse time, so an unknown
// format here is defensive: it surfaces an explicit error rather than
// silently falling through to a default.
func NewDetailRenderer(format appcontracts.OutputFormat) (DetailRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return DetailJSONRenderer{}, nil
	case appcontracts.FormatText:
		return DetailTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}

// detailGatingError returns the post-render exit-code error for the
// finding detail view. runDetailMode only runs after InspectViolation
// has confirmed a violation, so the detail view is always rendering a
// known violation — emit the gating exit code unless the operator
// asked for JSON, where the document itself carries the violation
// signal. The json/text decision lives here in a typed switch rather
// than in an inline bool branch at the call site.
func detailGatingError(format appcontracts.OutputFormat) error {
	if format.IsJSON() {
		return nil
	}
	return ui.ErrViolationsFound
}
