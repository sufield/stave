package trendcmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/forecast"
	"github.com/sufield/stave/internal/app/oscillation"
	"github.com/sufield/stave/internal/app/trendpredict"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// InputError marks a user-input failure (unknown --format on a subcommand).
// The pkg/stave facade maps it to stave.ErrInvalidInput so the subcommands
// exit 2 — matching their pre-facade ui.UserError handling. The main `trend`
// command never wrapped its format error, so [renderTrend] returns a plain
// error there (exit 4): the difference is preserved verbatim.
type InputError struct{ Err error }

// Error implements error.
func (e *InputError) Error() string { return e.Err.Error() }

// Unwrap exposes the wrapped cause.
func (e *InputError) Unwrap() error { return e.Err }

// renderTrend dispatches the main trend report. Unknown formats are a PLAIN
// error (the pre-facade command returned NewRenderer's error unwrapped → exit 4).
func renderTrend(format string, w io.Writer, r *trendReport) error {
	switch format {
	case "json":
		return renderTrendJSON(w, r)
	case "openmetrics":
		return renderTrendOpenMetrics(w, r)
	case "executive-summary":
		return renderExecutiveSummary(w, r)
	case "table", "":
		return renderTrendTable(w, r)
	}
	return fmt.Errorf("unsupported format %q (expected: table | json | openmetrics | executive-summary)", format)
}

// renderForecast dispatches the forecast result. Unknown format → InputError (exit 2).
func renderForecast(format string, w io.Writer, r *forecast.Result) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "table", "":
		writeForecastTable(w, r)
		return nil
	}
	return &InputError{fmt.Errorf("unsupported format %q (expected: table | json)", format)}
}

// renderOscillation dispatches the oscillation results. Unknown format → InputError (exit 2).
func renderOscillation(format string, w io.Writer, results []oscillation.Classification) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "table", "":
		writeOscillationTable(w, results)
		return nil
	}
	return &InputError{fmt.Errorf("unsupported format %q (expected: table | json)", format)}
}

// renderPredict dispatches the prediction. Unknown format → InputError (exit 2).
func renderPredict(format string, w io.Writer, p *trendpredict.Prediction) error {
	switch format {
	case "json":
		if err := jsonutil.WriteIndented(w, p); err != nil {
			return fmt.Errorf("render output: %w", err)
		}
		return nil
	case "text", "":
		return renderPredictText(w, p)
	}
	return &InputError{fmt.Errorf("unsupported format %q (expected: text | json)", format)}
}
