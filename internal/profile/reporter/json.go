package reporter

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/internal/profile"
)

// JSONReporter writes a structured JSON report.
type JSONReporter struct{}

// jsonReport wraps Report with metadata and disclaimer.
type jsonReport struct {
	Meta       ReportMeta     `json:"meta"`
	Report     profile.Report `json:"report"`
	Disclaimer string         `json:"disclaimer"`
}

// Write renders the report as indented JSON.
func (JSONReporter) Write(w io.Writer, report profile.Report, meta ReportMeta) error {
	out := jsonReport{
		Meta:       meta,
		Report:     report,
		Disclaimer: disclaimer,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
