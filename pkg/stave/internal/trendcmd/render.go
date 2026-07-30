package trendcmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/forecast"
	"github.com/sufield/stave/internal/app/oscillation"
	"github.com/sufield/stave/internal/app/trendpredict"
	"github.com/sufield/stave/internal/util/jsonutil"
	"github.com/sufield/stave/pkg/stave/internal/cmderr"
)

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
	return &cmderr.InputError{Err: fmt.Errorf("unsupported format %q (expected: table | json)", format)}
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
	return &cmderr.InputError{Err: fmt.Errorf("unsupported format %q (expected: table | json)", format)}
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
	return &cmderr.InputError{Err: fmt.Errorf("unsupported format %q (expected: text | json)", format)}
}
