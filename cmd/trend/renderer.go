package trend

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/forecast"
	"github.com/sufield/stave/internal/app/oscillation"
	"github.com/sufield/stave/internal/app/trendpredict"
	"github.com/sufield/stave/internal/util/jsonutil"
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

// The forecast, oscillation, and predict subcommands each render a
// different payload type, so each gets its own Renderer interface
// keyed by the payload it renders. The factories share the
// format-string contract but the concrete types and dispatch tables
// are per-mode. Same shape as cmd/nep and cmd/consolidate.

// --- ForecastRenderer ---

// ForecastRenderer renders the posture-score forecast result.
// Two formats: json and the default human-readable table.
type ForecastRenderer interface {
	Render(w io.Writer, r *forecast.Result) error
}

// ForecastJSONRenderer encodes the forecast result as JSON.
type ForecastJSONRenderer struct{}

// Render implements ForecastRenderer.
func (ForecastJSONRenderer) Render(w io.Writer, r *forecast.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ForecastTableRenderer writes the default human-readable table.
type ForecastTableRenderer struct{}

// Render implements ForecastRenderer.
func (ForecastTableRenderer) Render(w io.Writer, r *forecast.Result) error {
	writeForecastTable(w, r)
	return nil
}

// NewForecastRenderer maps a format string to its concrete renderer.
func NewForecastRenderer(format string) (ForecastRenderer, error) {
	switch format {
	case "json":
		return ForecastJSONRenderer{}, nil
	case "table", "":
		return ForecastTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// --- OscillationRenderer ---

// OscillationRenderer renders the oscillation classification results.
// Two formats: json and the default human-readable table.
type OscillationRenderer interface {
	Render(w io.Writer, results []oscillation.Classification) error
}

// OscillationJSONRenderer encodes the classification results as JSON.
type OscillationJSONRenderer struct{}

// Render implements OscillationRenderer.
func (OscillationJSONRenderer) Render(w io.Writer, results []oscillation.Classification) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// OscillationTableRenderer writes the default human-readable table.
type OscillationTableRenderer struct{}

// Render implements OscillationRenderer.
func (OscillationTableRenderer) Render(w io.Writer, results []oscillation.Classification) error {
	writeOscillationTable(w, results)
	return nil
}

// NewOscillationRenderer maps a format string to its concrete renderer.
func NewOscillationRenderer(format string) (OscillationRenderer, error) {
	switch format {
	case "json":
		return OscillationJSONRenderer{}, nil
	case "table", "":
		return OscillationTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// --- PredictRenderer ---

// PredictRenderer renders the compliance-readiness prediction.
// Two formats: json and the default human-readable text view.
type PredictRenderer interface {
	Render(w io.Writer, p *trendpredict.Prediction) error
}

// PredictJSONRenderer encodes the prediction as JSON.
type PredictJSONRenderer struct{}

// Render implements PredictRenderer.
func (PredictJSONRenderer) Render(w io.Writer, p *trendpredict.Prediction) error {
	if err := jsonutil.WriteIndented(w, p); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// PredictTextRenderer writes the default human-readable text view.
type PredictTextRenderer struct{}

// Render implements PredictRenderer.
func (PredictTextRenderer) Render(w io.Writer, p *trendpredict.Prediction) error {
	return renderPredictText(w, p)
}

// NewPredictRenderer maps a format string to its concrete renderer.
// Empty string maps to the text default, matching predict's prior
// behavior.
func NewPredictRenderer(format string) (PredictRenderer, error) {
	switch format {
	case "json":
		return PredictJSONRenderer{}, nil
	case "text", "":
		return PredictTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
