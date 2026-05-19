package trend

import (
	"fmt"
	"io"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave trend`. Four formats: json, openmetrics, executive-summary,
// and the default human-readable table.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r *trendReport) error
}

// JSONRenderer encodes the trend report as JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *trendReport) error {
	return renderTrendJSON(w, r)
}

// OpenMetricsRenderer emits the trend report in OpenMetrics
// text-exposition form.
type OpenMetricsRenderer struct{}

// Render implements Renderer.
func (OpenMetricsRenderer) Render(w io.Writer, r *trendReport) error {
	return renderTrendOpenMetrics(w, r)
}

// ExecutiveSummaryRenderer emits the higher-level executive summary
// view of the trend report.
type ExecutiveSummaryRenderer struct{}

// Render implements Renderer.
func (ExecutiveSummaryRenderer) Render(w io.Writer, r *trendReport) error {
	return renderExecutiveSummary(w, r)
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, r *trendReport) error {
	return renderTrendTable(w, r)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as table.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "openmetrics":
		return OpenMetricsRenderer{}, nil
	case "executive-summary":
		return ExecutiveSummaryRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | openmetrics | executive-summary)", format)
}
