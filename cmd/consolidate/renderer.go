package consolidate

import (
	"encoding/json"
	"fmt"
	"io"

	appconsolidate "github.com/sufield/stave/internal/app/consolidate"
	"github.com/sufield/stave/internal/app/orgtrend"
	"github.com/sufield/stave/internal/app/outlieranalysis"
)

// `stave consolidate` is one command with three operational modes
// — default consolidation, --diff-control outlier analysis, and
// --history org-trend — each rendering a different payload type.
// Each mode gets its own Renderer interface keyed by the payload it
// renders; the factories share the format-string contract but the
// concrete types and dispatch tables are per-mode. This is the same
// shape established in cmd/apply (NewOnlyRenderer) and
// cmd/diagnose (ExplainNarrativeRenderer) for packages that host
// multiple output surfaces.

// ConsolidatedRenderer renders the main multi-account consolidation
// report. TextRenderer carries the focus-account filter because
// WriteTextReport takes it as a parameter.
type ConsolidatedRenderer interface {
	Render(w io.Writer, r *appconsolidate.ConsolidatedReport) error
}

// ConsolidatedJSONRenderer encodes the report as indented JSON.
type ConsolidatedJSONRenderer struct{}

// Render implements ConsolidatedRenderer.
func (ConsolidatedJSONRenderer) Render(w io.Writer, r *appconsolidate.ConsolidatedReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ConsolidatedTextRenderer writes the default human-readable
// consolidation report.
type ConsolidatedTextRenderer struct {
	FocusAccount string
}

// Render implements ConsolidatedRenderer.
func (r ConsolidatedTextRenderer) Render(w io.Writer, rep *appconsolidate.ConsolidatedReport) error {
	appconsolidate.WriteTextReport(w, rep, r.FocusAccount)
	return nil
}

// NewConsolidatedRenderer maps a format string to a renderer for
// the main consolidate output. Returns an error for unknown formats.
func NewConsolidatedRenderer(format, focusAccount string) (ConsolidatedRenderer, error) {
	switch format {
	case "json":
		return ConsolidatedJSONRenderer{}, nil
	case "table", "":
		return ConsolidatedTextRenderer{FocusAccount: focusAccount}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// DiffRenderer renders an outlier-analysis report from --diff-control.
type DiffRenderer interface {
	Render(w io.Writer, r outlieranalysis.OutlierReport) error
}

// DiffJSONRenderer encodes the outlier report as indented JSON.
type DiffJSONRenderer struct{}

// Render implements DiffRenderer.
func (DiffJSONRenderer) Render(w io.Writer, r outlieranalysis.OutlierReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// DiffTableRenderer writes the default human-readable outlier table.
type DiffTableRenderer struct{}

// Render implements DiffRenderer.
func (DiffTableRenderer) Render(w io.Writer, r outlieranalysis.OutlierReport) error {
	writeDiffTable(w, r)
	return nil
}

// NewDiffRenderer maps a format string to a renderer for the
// --diff-control outlier-analysis output.
func NewDiffRenderer(format string) (DiffRenderer, error) {
	switch format {
	case "json":
		return DiffJSONRenderer{}, nil
	case "table", "":
		return DiffTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// HistoryRenderer renders the org-trend report from --history.
type HistoryRenderer interface {
	Render(w io.Writer, r *orgtrend.OrgTrendReport) error
}

// HistoryJSONRenderer encodes the trend report as indented JSON.
type HistoryJSONRenderer struct{}

// Render implements HistoryRenderer.
func (HistoryJSONRenderer) Render(w io.Writer, r *orgtrend.OrgTrendReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// HistoryMarkdownRenderer writes the markdown form of the trend report.
type HistoryMarkdownRenderer struct{}

// Render implements HistoryRenderer.
func (HistoryMarkdownRenderer) Render(w io.Writer, r *orgtrend.OrgTrendReport) error {
	writeHistoryMarkdown(w, r)
	return nil
}

// HistoryTableRenderer writes the default human-readable trend table.
type HistoryTableRenderer struct{}

// Render implements HistoryRenderer.
func (HistoryTableRenderer) Render(w io.Writer, r *orgtrend.OrgTrendReport) error {
	writeHistoryTable(w, r)
	return nil
}

// NewHistoryRenderer maps a format string to a renderer for the
// --history org-trend output.
func NewHistoryRenderer(format string) (HistoryRenderer, error) {
	switch format {
	case "json":
		return HistoryJSONRenderer{}, nil
	case "markdown":
		return HistoryMarkdownRenderer{}, nil
	case "table", "":
		return HistoryTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | markdown)", format)
}
